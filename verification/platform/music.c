/* Runtime composition of the existing Audio1/2/3 C handlers.
 * Handler structs are proof-domain snapshots, NOT live WRAM. These adapters
 * gather/scatter the exact fields in ram/wram.asm and follow every returned
 * continuation until a timed note or return. No SM83 instructions execute.
 * ROM bytes always come from immutable backing: audio must not steal the
 * game's currently selected ROM window.
 */
#include "platform.h"
#include <stdio.h>
#include <string.h>

static unsigned audio_variant(unsigned bank) { return bank == 2 ? 1 : bank == 8 ? 2 : 3; }
static uint16_t audio_word(const uint8_t *m, unsigned a) { return m[a] | (m[a+1] << 8); }
static uint8_t audio_byte(const uint8_t *m, unsigned bank, unsigned a)
{
    if (a < 0x4000) return m[PORT_ROM_BACKING_BASE + a];
    if (a >= 0x8000 || bank >= PORT_ROM_BANK_COUNT) return 0xff;
    return m[PORT_ROM_BACKING_BASE + bank * 0x4000 + a - 0x4000];
}

struct audio_field { size_t offset; unsigned address, count, stride; };
#define FIELD(type, field, address, stride) { offsetof(struct type, field), address, sizeof(((struct type *)0)->field), stride }
static void audio_fields(void *snapshot, uint8_t *m, const struct audio_field *fields, size_t count, int write)
{
    uint8_t *s = snapshot;
    for (size_t f = 0; f < count; ++f)
        for (unsigned i = 0; i < fields[f].count; ++i) {
            unsigned a = fields[f].address + i * fields[f].stride;
            if (write) m[a] = s[fields[f].offset + i];
            else s[fields[f].offset + i] = m[a];
        }
}
/* Frequency pairs are strided by five hardware registers per channel. */
static void audio_frequencies(uint8_t *v, uint8_t *m, int write)
{
    for (unsigned i = 0; i < 8; ++i) {
        unsigned a = 0xff13 + (i / 2) * 5 + i % 2;
        if (write) m[a] = v[i]; else v[i] = m[a];
    }
}

static const struct audio_field fields_sound_ret[] = {
    FIELD(audio_sound_ret_state, command_pointers, 0xc006, 1),
    FIELD(audio_sound_ret_state, return_addresses, 0xc016, 1),
    FIELD(audio_sound_ret_state, flags1, 0xc02e, 1),
    FIELD(audio_sound_ret_state, flags2, 0xc036, 1),
    FIELD(audio_sound_ret_state, disable_channel_output, 0xc003, 1),
    FIELD(audio_sound_ret_state, audio3_enable, 0xff1a, 1),
    FIELD(audio_sound_ret_state, audio_terminal, 0xff25, 1),
    FIELD(audio_sound_ret_state, sound_ids, 0xc026, 1),
    FIELD(audio_sound_ret_state, saved_volume, 0xc005, 1),
    FIELD(audio_sound_ret_state, audio_volume, 0xff24, 1),
};
void port_audio1_sound_ret(struct audio_sound_ret_state *);
void port_audio2_sound_ret(struct audio_sound_ret_state *);
void port_audio3_sound_ret(struct audio_sound_ret_state *);
static unsigned run_sound_ret(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_sound_ret_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_sound_ret, sizeof(fields_sound_ret) / sizeof(fields_sound_ret[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    /* sound_ret may pop the one-level music call and fetch at that address. */
    if (s.command_bytes[0] == 0xff && (s.flags1[r->c] & 2))
        s.command_bytes[1] = audio_byte(m, bank, audio_word(m, 0xc016 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_sound_ret(&s); break;
    case 2: port_audio2_sound_ret(&s); break;
    default: port_audio3_sound_ret(&s); break;
    }
    audio_fields(&s, m, fields_sound_ret, sizeof(fields_sound_ret) / sizeof(fields_sound_ret[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_sound_call[] = {
    FIELD(audio_sound_call_state, command_pointers, 0xc006, 1),
    FIELD(audio_sound_call_state, return_addresses, 0xc016, 1),
    FIELD(audio_sound_call_state, flags1, 0xc02e, 1),
};
void port_audio1_sound_call(struct audio_sound_call_state *);
void port_audio2_sound_call(struct audio_sound_call_state *);
void port_audio3_sound_call(struct audio_sound_call_state *);
static unsigned run_sound_call(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_sound_call_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_sound_call, sizeof(fields_sound_call) / sizeof(fields_sound_call[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    switch (audio_variant(bank)) {
    case 1: port_audio1_sound_call(&s); break;
    case 2: port_audio2_sound_call(&s); break;
    default: port_audio3_sound_call(&s); break;
    }
    audio_fields(&s, m, fields_sound_call, sizeof(fields_sound_call) / sizeof(fields_sound_call[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_sound_loop[] = {
    FIELD(audio_sound_loop_state, command_pointers, 0xc006, 1),
    FIELD(audio_sound_loop_state, loop_counters, 0xc0be, 1),
};
void port_audio1_sound_loop(struct audio_sound_loop_state *);
void port_audio2_sound_loop(struct audio_sound_loop_state *);
void port_audio3_sound_loop(struct audio_sound_loop_state *);
static unsigned run_sound_loop(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_sound_loop_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_sound_loop, sizeof(fields_sound_loop) / sizeof(fields_sound_loop[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    switch (audio_variant(bank)) {
    case 1: port_audio1_sound_loop(&s); break;
    case 2: port_audio2_sound_loop(&s); break;
    default: port_audio3_sound_loop(&s); break;
    }
    audio_fields(&s, m, fields_sound_loop, sizeof(fields_sound_loop) / sizeof(fields_sound_loop[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_note_type[] = {
    FIELD(audio_note_type_state, command_pointers, 0xc006, 1),
    FIELD(audio_note_type_state, note_speeds, 0xc0c6, 1),
    FIELD(audio_note_type_state, volumes, 0xc0de, 1),
    FIELD(audio_note_type_state, music_wave_instrument, 0xc0e6, 1),
    FIELD(audio_note_type_state, sfx_wave_instrument, 0xc0e7, 1),
};
void port_audio1_note_type(struct audio_note_type_state *);
void port_audio2_note_type(struct audio_note_type_state *);
void port_audio3_note_type(struct audio_note_type_state *);
static unsigned run_note_type(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_note_type_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_note_type, sizeof(fields_note_type) / sizeof(fields_note_type[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_note_type(&s); break;
    case 2: port_audio2_note_type(&s); break;
    default: port_audio3_note_type(&s); break;
    }
    audio_fields(&s, m, fields_note_type, sizeof(fields_note_type) / sizeof(fields_note_type[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_toggle_perfect_pitch[] = {
    FIELD(audio_toggle_perfect_pitch_state, flags1, 0xc02e, 1),
};
void port_audio1_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *);
void port_audio2_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *);
void port_audio3_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *);
static unsigned run_toggle_perfect_pitch(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_toggle_perfect_pitch_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_toggle_perfect_pitch, sizeof(fields_toggle_perfect_pitch) / sizeof(fields_toggle_perfect_pitch[0]), 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_toggle_perfect_pitch(&s); break;
    case 2: port_audio2_toggle_perfect_pitch(&s); break;
    default: port_audio3_toggle_perfect_pitch(&s); break;
    }
    audio_fields(&s, m, fields_toggle_perfect_pitch, sizeof(fields_toggle_perfect_pitch) / sizeof(fields_toggle_perfect_pitch[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_vibrato[] = {
    FIELD(audio_vibrato_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_vibrato_command_state, delay_counters, 0xc04e, 1),
    FIELD(audio_vibrato_command_state, delay_reloads, 0xc06e, 1),
    FIELD(audio_vibrato_command_state, extents, 0xc056, 1),
    FIELD(audio_vibrato_command_state, rates, 0xc05e, 1),
};
void port_audio1_vibrato(struct audio_vibrato_command_state *);
void port_audio2_vibrato(struct audio_vibrato_command_state *);
void port_audio3_vibrato(struct audio_vibrato_command_state *);
static unsigned run_vibrato(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_vibrato_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_vibrato, sizeof(fields_vibrato) / sizeof(fields_vibrato[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    switch (audio_variant(bank)) {
    case 1: port_audio1_vibrato(&s); break;
    case 2: port_audio2_vibrato(&s); break;
    default: port_audio3_vibrato(&s); break;
    }
    audio_fields(&s, m, fields_vibrato, sizeof(fields_vibrato) / sizeof(fields_vibrato[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_pitch_slide[] = {
    FIELD(audio_pitch_slide_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_pitch_slide_command_state, length_modifiers, 0xc076, 1),
    FIELD(audio_pitch_slide_command_state, target_frequency_high, 0xc0a6, 1),
    FIELD(audio_pitch_slide_command_state, target_frequency_low, 0xc0ae, 1),
    FIELD(audio_pitch_slide_command_state, flags1, 0xc02e, 1),
};
void port_audio1_pitch_slide(struct audio_pitch_slide_command_state *);
void port_audio2_pitch_slide(struct audio_pitch_slide_command_state *);
void port_audio3_pitch_slide(struct audio_pitch_slide_command_state *);
static unsigned run_pitch_slide(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_pitch_slide_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_pitch_slide, sizeof(fields_pitch_slide) / sizeof(fields_pitch_slide[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    switch (audio_variant(bank)) {
    case 1: port_audio1_pitch_slide(&s); break;
    case 2: port_audio2_pitch_slide(&s); break;
    default: port_audio3_pitch_slide(&s); break;
    }
    audio_fields(&s, m, fields_pitch_slide, sizeof(fields_pitch_slide) / sizeof(fields_pitch_slide[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_duty_cycle[] = {
    FIELD(audio_duty_cycle_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_duty_cycle_command_state, duty_cycles, 0xc03e, 1),
};
void port_audio1_duty_cycle(struct audio_duty_cycle_command_state *);
void port_audio2_duty_cycle(struct audio_duty_cycle_command_state *);
void port_audio3_duty_cycle(struct audio_duty_cycle_command_state *);
static unsigned run_duty_cycle(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_duty_cycle_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_duty_cycle, sizeof(fields_duty_cycle) / sizeof(fields_duty_cycle[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_duty_cycle(&s); break;
    case 2: port_audio2_duty_cycle(&s); break;
    default: port_audio3_duty_cycle(&s); break;
    }
    audio_fields(&s, m, fields_duty_cycle, sizeof(fields_duty_cycle) / sizeof(fields_duty_cycle[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_tempo[] = {
    FIELD(audio_tempo_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_tempo_command_state, music_tempo, 0xc0e8, 1),
    FIELD(audio_tempo_command_state, sfx_tempo, 0xc0ea, 1),
    FIELD(audio_tempo_command_state, fractional_note_delays, 0xc0ce, 1),
};
void port_audio1_tempo(struct audio_tempo_command_state *);
void port_audio2_tempo(struct audio_tempo_command_state *);
void port_audio3_tempo(struct audio_tempo_command_state *);
static unsigned run_tempo(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_tempo_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_tempo, sizeof(fields_tempo) / sizeof(fields_tempo[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    switch (audio_variant(bank)) {
    case 1: port_audio1_tempo(&s); break;
    case 2: port_audio2_tempo(&s); break;
    default: port_audio3_tempo(&s); break;
    }
    audio_fields(&s, m, fields_tempo, sizeof(fields_tempo) / sizeof(fields_tempo[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_stereo_panning[] = {
    FIELD(audio_byte_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_byte_command_state, value, 0xc004, 1),
};
void port_audio1_stereo_panning(struct audio_byte_command_state *);
void port_audio2_stereo_panning(struct audio_byte_command_state *);
void port_audio3_stereo_panning(struct audio_byte_command_state *);
static unsigned run_stereo_panning(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_byte_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_stereo_panning, sizeof(fields_stereo_panning) / sizeof(fields_stereo_panning[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_stereo_panning(&s); break;
    case 2: port_audio2_stereo_panning(&s); break;
    default: port_audio3_stereo_panning(&s); break;
    }
    audio_fields(&s, m, fields_stereo_panning, sizeof(fields_stereo_panning) / sizeof(fields_stereo_panning[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_unknownmusic0xef[] = {
    FIELD(audio_unknown_ef_state, audio_ram, 0xc000, 1),
    FIELD(audio_unknown_ef_state, hardware_audio, 0xff10, 1),
};
void port_audio1_unknownmusic0xef(struct audio_unknown_ef_state *);
void port_audio2_unknownmusic0xef(struct audio_unknown_ef_state *);
void port_audio3_unknownmusic0xef(struct audio_unknown_ef_state *);
static unsigned run_unknownmusic0xef(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_unknown_ef_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_unknownmusic0xef, sizeof(fields_unknownmusic0xef) / sizeof(fields_unknownmusic0xef[0]), 0);
    for (unsigned i = 0; i < sizeof(s.header_rom); ++i) s.header_rom[i] = audio_byte(m, bank, 0x4000 + i);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_unknownmusic0xef(&s); break;
    case 2: port_audio2_unknownmusic0xef(&s); break;
    default: port_audio3_unknownmusic0xef(&s); break;
    }
    audio_fields(&s, m, fields_unknownmusic0xef, sizeof(fields_unknownmusic0xef) / sizeof(fields_unknownmusic0xef[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_duty_cycle_pattern[] = {
    FIELD(audio_duty_pattern_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_duty_pattern_command_state, duty_patterns, 0xc046, 1),
    FIELD(audio_duty_pattern_command_state, duty_cycles, 0xc03e, 1),
    FIELD(audio_duty_pattern_command_state, flags1, 0xc02e, 1),
};
void port_audio1_duty_cycle_pattern(struct audio_duty_pattern_command_state *);
void port_audio2_duty_cycle_pattern(struct audio_duty_pattern_command_state *);
void port_audio3_duty_cycle_pattern(struct audio_duty_pattern_command_state *);
static unsigned run_duty_cycle_pattern(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_duty_pattern_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_duty_cycle_pattern, sizeof(fields_duty_cycle_pattern) / sizeof(fields_duty_cycle_pattern[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_duty_cycle_pattern(&s); break;
    case 2: port_audio2_duty_cycle_pattern(&s); break;
    default: port_audio3_duty_cycle_pattern(&s); break;
    }
    audio_fields(&s, m, fields_duty_cycle_pattern, sizeof(fields_duty_cycle_pattern) / sizeof(fields_duty_cycle_pattern[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_volume[] = {
    FIELD(audio_byte_command_state, command_pointers, 0xc006, 1),
    FIELD(audio_byte_command_state, value, 0xff24, 1),
};
void port_audio1_volume(struct audio_byte_command_state *);
void port_audio2_volume(struct audio_byte_command_state *);
void port_audio3_volume(struct audio_byte_command_state *);
static unsigned run_volume(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_byte_command_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_volume, sizeof(fields_volume) / sizeof(fields_volume[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_volume(&s); break;
    case 2: port_audio2_volume(&s); break;
    default: port_audio3_volume(&s); break;
    }
    audio_fields(&s, m, fields_volume, sizeof(fields_volume) / sizeof(fields_volume[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_execute_music[] = {
    FIELD(audio_execute_music_state, flags2, 0xc036, 1),
};
void port_audio1_execute_music(struct audio_execute_music_state *);
void port_audio2_execute_music(struct audio_execute_music_state *);
void port_audio3_execute_music(struct audio_execute_music_state *);
static unsigned run_execute_music(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_execute_music_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_execute_music, sizeof(fields_execute_music) / sizeof(fields_execute_music[0]), 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_execute_music(&s); break;
    case 2: port_audio2_execute_music(&s); break;
    default: port_audio3_execute_music(&s); break;
    }
    audio_fields(&s, m, fields_execute_music, sizeof(fields_execute_music) / sizeof(fields_execute_music[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_octave[] = {
    FIELD(audio_octave_state, octaves, 0xc0d6, 1),
};
void port_audio1_octave(struct audio_octave_state *);
void port_audio2_octave(struct audio_octave_state *);
void port_audio3_octave(struct audio_octave_state *);
static unsigned run_octave(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_octave_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_octave, sizeof(fields_octave) / sizeof(fields_octave[0]), 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_octave(&s); break;
    case 2: port_audio2_octave(&s); break;
    default: port_audio3_octave(&s); break;
    }
    audio_fields(&s, m, fields_octave, sizeof(fields_octave) / sizeof(fields_octave[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_sfx_note[] = {
    FIELD(audio_sfx_note_state, command_pointers, 0xc006, 1),
    FIELD(audio_sfx_note_state, note_speeds, 0xc0c6, 1),
    FIELD(audio_sfx_note_state, music_tempo, 0xc0e8, 1),
    FIELD(audio_sfx_note_state, sfx_tempo, 0xc0ea, 1),
    FIELD(audio_sfx_note_state, fractional_note_delays, 0xc0ce, 1),
    FIELD(audio_sfx_note_state, note_delays, 0xc0b6, 1),
    FIELD(audio_sfx_note_state, flags2, 0xc036, 1),
    FIELD(audio_sfx_note_state, flags1, 0xc02e, 1),
    FIELD(audio_sfx_note_state, sound_ids, 0xc026, 1),
    FIELD(audio_sfx_note_state, tempo_modifier, 0xc0f2, 1),
    FIELD(audio_sfx_note_state, duty_cycles, 0xc03e, 1),
    FIELD(audio_sfx_note_state, hardware_volume_envelopes, 0xff12, 5),
    FIELD(audio_sfx_note_state, hardware_duty_registers, 0xff11, 5),
    FIELD(audio_sfx_note_state, audio_terminal, 0xff25, 1),
    FIELD(audio_sfx_note_state, stereo_panning, 0xc004, 1),
    FIELD(audio_sfx_note_state, music_wave_instrument, 0xc0e6, 1),
    FIELD(audio_sfx_note_state, sfx_wave_instrument, 0xc0e7, 1),
    FIELD(audio_sfx_note_state, frequency_modifier, 0xc0f1, 1),
    FIELD(audio_sfx_note_state, audio3_enable, 0xff1a, 1),
    FIELD(audio_sfx_note_state, wave_ram, 0xff30, 1),
};
void port_audio1_sfx_note(struct audio_sfx_note_state *);
void port_audio2_sfx_note(struct audio_sfx_note_state *);
void port_audio3_sfx_note(struct audio_sfx_note_state *);
static unsigned run_sfx_note(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_sfx_note_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_sfx_note, sizeof(fields_sfx_note) / sizeof(fields_sfx_note[0]), 0);
    unsigned pointer = audio_word(m, 0xc006 + 2 * r->c);
    for (unsigned i = 0; i < sizeof(s.command_bytes); ++i) s.command_bytes[i] = audio_byte(m, bank, (uint16_t)(pointer + i));
    audio_frequencies(s.hardware_frequency_registers, m, 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_sfx_note(&s); break;
    case 2: port_audio2_sfx_note(&s); break;
    default: port_audio3_sfx_note(&s); break;
    }
    audio_fields(&s, m, fields_sfx_note, sizeof(fields_sfx_note) / sizeof(fields_sfx_note[0]), 1);
    audio_frequencies(s.hardware_frequency_registers, m, 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_pitch_sweep[] = {
    FIELD(audio_pitch_sweep_state, command_pointers, 0xc006, 1),
    FIELD(audio_pitch_sweep_state, flags2, 0xc036, 1),
    FIELD(audio_pitch_sweep_state, sweep, 0xff10, 1),
};
void port_audio1_pitch_sweep(struct audio_pitch_sweep_state *);
void port_audio2_pitch_sweep(struct audio_pitch_sweep_state *);
void port_audio3_pitch_sweep(struct audio_pitch_sweep_state *);
static unsigned run_pitch_sweep(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_pitch_sweep_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_pitch_sweep, sizeof(fields_pitch_sweep) / sizeof(fields_pitch_sweep[0]), 0);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_pitch_sweep(&s); break;
    case 2: port_audio2_pitch_sweep(&s); break;
    default: port_audio3_pitch_sweep(&s); break;
    }
    audio_fields(&s, m, fields_pitch_sweep, sizeof(fields_pitch_sweep) / sizeof(fields_pitch_sweep[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_note[] = {
    FIELD(audio_note_state, audio_ram, 0xc000, 1),
    FIELD(audio_note_state, hardware_audio, 0xff10, 1),
};
void port_audio1_note(struct audio_note_state *);
void port_audio2_note(struct audio_note_state *);
void port_audio3_note(struct audio_note_state *);
static unsigned run_note(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_note_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_note, sizeof(fields_note) / sizeof(fields_note[0]), 0);
    for (unsigned i = 0; i < sizeof(s.header_rom); ++i) s.header_rom[i] = audio_byte(m, bank, 0x4000 + i);
    s.command_byte = audio_byte(m, bank, audio_word(m, 0xc006 + 2 * r->c));
    switch (audio_variant(bank)) {
    case 1: port_audio1_note(&s); break;
    case 2: port_audio2_note(&s); break;
    default: port_audio3_note(&s); break;
    }
    audio_fields(&s, m, fields_note, sizeof(fields_note) / sizeof(fields_note[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_note_length[] = {
    FIELD(audio_note_length_state, note_speeds, 0xc0c6, 1),
    FIELD(audio_note_length_state, music_tempo, 0xc0e8, 1),
    FIELD(audio_note_length_state, sfx_tempo, 0xc0ea, 1),
    FIELD(audio_note_length_state, fractional_note_delays, 0xc0ce, 1),
    FIELD(audio_note_length_state, note_delays, 0xc0b6, 1),
    FIELD(audio_note_length_state, flags2, 0xc036, 1),
    FIELD(audio_note_length_state, flags1, 0xc02e, 1),
    FIELD(audio_note_length_state, channel5_sound_id, 0xc02a, 1),
    FIELD(audio_note_length_state, channel8_sound_id, 0xc02d, 1),
    FIELD(audio_note_length_state, tempo_modifier, 0xc0f2, 1),
};
void port_audio1_note_length(struct audio_note_length_state *);
void port_audio2_note_length(struct audio_note_length_state *);
void port_audio3_note_length(struct audio_note_length_state *);
static unsigned run_note_length(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_note_length_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_note_length, sizeof(fields_note_length) / sizeof(fields_note_length[0]), 0);
    s.saved_a = *saved_a;
    s.saved_f = *saved_f;
    switch (audio_variant(bank)) {
    case 1: port_audio1_note_length(&s); break;
    case 2: port_audio2_note_length(&s); break;
    default: port_audio3_note_length(&s); break;
    }
    audio_fields(&s, m, fields_note_length, sizeof(fields_note_length) / sizeof(fields_note_length[0]), 1);
    *saved_a = s.saved_a;
    *saved_f = s.saved_f;
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_note_pitch[] = {
    FIELD(audio_note_pitch_state, octaves, 0xc0d6, 1),
    FIELD(audio_note_pitch_state, flags1, 0xc02e, 1),
    FIELD(audio_note_pitch_state, sfx_sound_ids, 0xc02a, 1),
    FIELD(audio_note_pitch_state, volumes, 0xc0de, 1),
    FIELD(audio_note_pitch_state, note_delays, 0xc0b6, 1),
    FIELD(audio_note_pitch_state, duty_cycles, 0xc03e, 1),
    FIELD(audio_note_pitch_state, hardware_volume_envelopes, 0xff12, 5),
    FIELD(audio_note_pitch_state, hardware_duty_registers, 0xff11, 5),
    FIELD(audio_note_pitch_state, audio_terminal, 0xff25, 1),
    FIELD(audio_note_pitch_state, stereo_panning, 0xc004, 1),
    FIELD(audio_note_pitch_state, frequency_low_bytes, 0xc066, 1),
    FIELD(audio_note_pitch_state, music_wave_instrument, 0xc0e6, 1),
    FIELD(audio_note_pitch_state, sfx_wave_instrument, 0xc0e7, 1),
    FIELD(audio_note_pitch_state, channel5_sound_id, 0xc02a, 1),
    FIELD(audio_note_pitch_state, channel8_sound_id, 0xc02d, 1),
    FIELD(audio_note_pitch_state, frequency_modifier, 0xc0f1, 1),
    FIELD(audio_note_pitch_state, audio3_enable, 0xff1a, 1),
    FIELD(audio_note_pitch_state, wave_ram, 0xff30, 1),
    FIELD(audio_note_pitch_state, length_modifiers, 0xc076, 1),
    FIELD(audio_note_pitch_state, frequency_steps, 0xc07e, 1),
    FIELD(audio_note_pitch_state, frequency_steps_fractional, 0xc086, 1),
    FIELD(audio_note_pitch_state, current_frequency_fractional, 0xc08e, 1),
    FIELD(audio_note_pitch_state, current_frequency_high, 0xc096, 1),
    FIELD(audio_note_pitch_state, current_frequency_low, 0xc09e, 1),
    FIELD(audio_note_pitch_state, target_frequency_high, 0xc0a6, 1),
    FIELD(audio_note_pitch_state, target_frequency_low, 0xc0ae, 1),
};
void port_audio1_note_pitch(struct audio_note_pitch_state *);
void port_audio2_note_pitch(struct audio_note_pitch_state *);
void port_audio3_note_pitch(struct audio_note_pitch_state *);
static unsigned run_note_pitch(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_note_pitch_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_note_pitch, sizeof(fields_note_pitch) / sizeof(fields_note_pitch[0]), 0);
    s.saved_a = *saved_a;
    s.saved_f = *saved_f;
    audio_frequencies(s.hardware_frequency_registers, m, 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_note_pitch(&s); break;
    case 2: port_audio2_note_pitch(&s); break;
    default: port_audio3_note_pitch(&s); break;
    }
    audio_fields(&s, m, fields_note_pitch, sizeof(fields_note_pitch) / sizeof(fields_note_pitch[0]), 1);
    *saved_a = s.saved_a;
    *saved_f = s.saved_f;
    audio_frequencies(s.hardware_frequency_registers, m, 1);
    *r = s.registers;
    return AUDIO_CONTINUE_RETURN;
}

static const struct audio_field fields_play_next_note[] = {
    FIELD(audio_play_next_note_state, vibrato_delay_reloads, 0xc06e, 1),
    FIELD(audio_play_next_note_state, vibrato_delay_counters, 0xc04e, 1),
    FIELD(audio_play_next_note_state, flags1, 0xc02e, 1),
    FIELD(audio_play_next_note_state, low_health_alarm, 0xd083, 1),
};
void port_audio1_play_next_note(struct audio_play_next_note_state *);
void port_audio2_play_next_note(struct audio_play_next_note_state *);
void port_audio3_play_next_note(struct audio_play_next_note_state *);
static unsigned run_play_next_note(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_play_next_note_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_play_next_note, sizeof(fields_play_next_note) / sizeof(fields_play_next_note[0]), 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_play_next_note(&s); break;
    case 2: port_audio2_play_next_note(&s); break;
    default: port_audio3_play_next_note(&s); break;
    }
    audio_fields(&s, m, fields_play_next_note, sizeof(fields_play_next_note) / sizeof(fields_play_next_note[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_apply_music_affects[] = {
    FIELD(audio_apply_music_affects_state, note_delays, 0xc0b6, 1),
    FIELD(audio_apply_music_affects_state, sound_ids, 0xc026, 1),
    FIELD(audio_apply_music_affects_state, flags1, 0xc02e, 1),
    FIELD(audio_apply_music_affects_state, flags2, 0xc036, 1),
    FIELD(audio_apply_music_affects_state, duty_patterns, 0xc046, 1),
    FIELD(audio_apply_music_affects_state, hardware_duty_registers, 0xff11, 5),
    FIELD(audio_apply_music_affects_state, vibrato_delay_counters, 0xc04e, 1),
    FIELD(audio_apply_music_affects_state, vibrato_extents, 0xc056, 1),
    FIELD(audio_apply_music_affects_state, vibrato_rates, 0xc05e, 1),
    FIELD(audio_apply_music_affects_state, frequency_low_bytes, 0xc066, 1),
    FIELD(audio_apply_music_affects_state, hardware_frequency_low_registers, 0xff13, 5),
};
void port_audio1_apply_music_affects(struct audio_apply_music_affects_state *);
void port_audio2_apply_music_affects(struct audio_apply_music_affects_state *);
void port_audio3_apply_music_affects(struct audio_apply_music_affects_state *);
static unsigned run_apply_music_affects(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_apply_music_affects_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_apply_music_affects, sizeof(fields_apply_music_affects) / sizeof(fields_apply_music_affects[0]), 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_apply_music_affects(&s); break;
    case 2: port_audio2_apply_music_affects(&s); break;
    default: port_audio3_apply_music_affects(&s); break;
    }
    audio_fields(&s, m, fields_apply_music_affects, sizeof(fields_apply_music_affects) / sizeof(fields_apply_music_affects[0]), 1);
    *r = s.registers;
    return s.continuation;
}

static const struct audio_field fields_apply_pitch_slide[] = {
    FIELD(audio_pitch_slide_state, flags1, 0xc02e, 1),
    FIELD(audio_pitch_slide_state, frequency_steps, 0xc07e, 1),
    FIELD(audio_pitch_slide_state, frequency_steps_fractional, 0xc086, 1),
    FIELD(audio_pitch_slide_state, current_frequency_fractional, 0xc08e, 1),
    FIELD(audio_pitch_slide_state, current_frequency_high, 0xc096, 1),
    FIELD(audio_pitch_slide_state, current_frequency_low, 0xc09e, 1),
    FIELD(audio_pitch_slide_state, target_frequency_high, 0xc0a6, 1),
    FIELD(audio_pitch_slide_state, target_frequency_low, 0xc0ae, 1),
};
void port_audio1_apply_pitch_slide(struct audio_pitch_slide_state *);
void port_audio2_apply_pitch_slide(struct audio_pitch_slide_state *);
void port_audio3_apply_pitch_slide(struct audio_pitch_slide_state *);
static unsigned run_apply_pitch_slide(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_pitch_slide_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_apply_pitch_slide, sizeof(fields_apply_pitch_slide) / sizeof(fields_apply_pitch_slide[0]), 0);
    audio_frequencies(s.hardware_frequency_registers, m, 0);
    switch (audio_variant(bank)) {
    case 1: port_audio1_apply_pitch_slide(&s); break;
    case 2: port_audio2_apply_pitch_slide(&s); break;
    default: port_audio3_apply_pitch_slide(&s); break;
    }
    audio_fields(&s, m, fields_apply_pitch_slide, sizeof(fields_apply_pitch_slide) / sizeof(fields_apply_pitch_slide[0]), 1);
    audio_frequencies(s.hardware_frequency_registers, m, 1);
    *r = s.registers;
    return AUDIO_CONTINUE_RETURN;
}

static const struct audio_field fields_play_sound[] = {
    FIELD(audio_play_sound_state, audio_ram, 0xc000, 1),
    FIELD(audio_play_sound_state, hardware_audio, 0xff10, 1),
};
void port_audio1_play_sound(struct audio_play_sound_state *);
void port_audio2_play_sound(struct audio_play_sound_state *);
void port_audio3_play_sound(struct audio_play_sound_state *);
static unsigned run_play_sound(uint8_t *m, unsigned bank, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    struct audio_play_sound_state s = {0};
    s.registers = *r;
    (void)bank; (void)saved_a; (void)saved_f;
    audio_fields(&s, m, fields_play_sound, sizeof(fields_play_sound) / sizeof(fields_play_sound[0]), 0);
    for (unsigned i = 0; i < sizeof(s.header_rom); ++i) s.header_rom[i] = audio_byte(m, bank, 0x4000 + i);
    switch (audio_variant(bank)) {
    case 1: port_audio1_play_sound(&s); break;
    case 2: port_audio2_play_sound(&s); break;
    default: port_audio3_play_sound(&s); break;
    }
    audio_fields(&s, m, fields_play_sound, sizeof(fields_play_sound) / sizeof(fields_play_sound[0]), 1);
    *r = s.registers;
    return AUDIO_CONTINUE_RETURN;
}

static unsigned audio_dispatch(uint8_t *m, unsigned bank, unsigned continuation, struct cpu_register_state *r, uint8_t *saved_a, uint8_t *saved_f)
{
    switch (continuation) {
    case AUDIO_CONTINUE_SOUND_RET: return run_sound_ret(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_SOUND_CALL: return run_sound_call(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_SOUND_LOOP: return run_sound_loop(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_NOTE_TYPE: return run_note_type(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_TOGGLE_PERFECT_PITCH: return run_toggle_perfect_pitch(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_VIBRATO: return run_vibrato(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_PITCH_SLIDE: return run_pitch_slide(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_DUTY_CYCLE: return run_duty_cycle(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_TEMPO: return run_tempo(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_STEREO_PANNING: return run_stereo_panning(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_UNKNOWN_EF: return run_unknownmusic0xef(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_DUTY_CYCLE_PATTERN: return run_duty_cycle_pattern(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_VOLUME: return run_volume(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_EXECUTE_MUSIC: return run_execute_music(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_OCTAVE: return run_octave(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_SFX_NOTE: return run_sfx_note(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_PITCH_SWEEP: return run_pitch_sweep(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_NOTE: return run_note(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_NOTE_LENGTH: return run_note_length(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_NOTE_PITCH: return run_note_pitch(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_PLAY_NEXT_NOTE: return run_play_next_note(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_APPLY_MUSIC_AFFECTS: return run_apply_music_affects(m, bank, r, saved_a, saved_f);
    case AUDIO_CONTINUE_APPLY_PITCH_SLIDE: return run_apply_pitch_slide(m, bank, r, saved_a, saved_f);
    default: return AUDIO_CONTINUE_RETURN;
    }
}

void music_play(uint8_t *m, unsigned bank, uint8_t sound)
{
    if (bank != 2 && bank != 8 && bank != 0x1f) return;
    m[0xc0ef] = (uint8_t)bank;
    m[0xc0f0] = (uint8_t)bank;
    m[0xff26] = 0x80;
    struct cpu_register_state r = {0};
    uint8_t saved_a = 0, saved_f = 0;
    r.a = sound;
    run_play_sound(m, bank, &r, &saved_a, &saved_f);
}

void port_play_sound(struct play_sound_state *);
void port_fade_out_audio(struct fade_out_audio_state *);
void port_music_do_low_health_alarm(struct music_low_health_alarm_state *);

static void home_audio_state(struct play_sound_state *s, uint8_t *m, int write)
{
    static const struct audio_field fields[] = {
        FIELD(play_sound_state, new_sound_id, 0xc0ee, 1),
        FIELD(play_sound_state, audio_rom_bank, 0xc0ef, 1),
        FIELD(play_sound_state, audio_saved_rom_bank, 0xc0f0, 1),
        FIELD(play_sound_state, fade_control, 0xcfc7, 1),
        FIELD(play_sound_state, fade_reload, 0xcfc8, 1),
        FIELD(play_sound_state, fade_counter, 0xcfc9, 1),
        FIELD(play_sound_state, last_music_sound_id, 0xcfca, 1),
        FIELD(play_sound_state, channel_sound_ids, 0xc02a, 1),
        FIELD(play_sound_state, low_health_alarm, 0xd083, 1),
    };
    audio_fields(s, m, fields, sizeof(fields) / sizeof(*fields), write);
    if (!write) { s->loaded_rom_bank = m[0xffb8]; s->rom_bank = m[0x2000]; }
}

void music_fade(uint8_t *m, unsigned bank, uint8_t sound, uint8_t ticks)
{
    if (bank != 2 && bank != 8 && bank != 0x1f) return;
    struct play_sound_state s = {0};
    home_audio_state(&s, m, 0);
    s.registers.a = sound;
    s.new_sound_id = sound;
    s.audio_saved_rom_bank = (uint8_t)bank;
    s.fade_control = ticks;
    port_play_sound(&s);
    home_audio_state(&s, m, 1);
    if (s.dispatch_called) music_play(m, bank, sound);
}

static void fade_tick(uint8_t *m)
{
    struct fade_out_audio_state s = {0};
    home_audio_state(&s.sound, m, 0);
    unsigned old_bank = s.sound.audio_rom_bank;
    uint8_t target = s.sound.fade_control;
    s.status_flags2 = m[0xd72c];
    s.audio_volume = m[0xff24];
    port_fade_out_audio(&s);
    home_audio_state(&s.sound, m, 1);
    m[0xff24] = s.audio_volume;
    if (target && !s.sound.fade_control) {
        /* The leaf exposes two PlaySound boundaries: stop the old engine,
         * then start the queued ID in the saved bank, in that order. */
        unsigned next_bank = s.sound.audio_saved_rom_bank;
        music_play(m, old_bank, 0xff);
        music_play(m, next_bank, target);
    }
}

void music_tick(uint8_t *m)
{
    /* VBlank calls FadeOutAudio before choosing the current engine bank. */
    fade_tick(m);
    unsigned bank = m[0xc0ef];
    if (bank != 2 && bank != 8 && bank != 0x1f) return;
    if (bank == 8) {
        struct music_low_health_alarm_state s = {0};
        s.low_health_alarm = m[0xd083];
        s.channel5_sound_id = m[0xc02a];
        memcpy(s.audio1_registers, m + 0xff10, 5);
        port_music_do_low_health_alarm(&s);
        m[0xd083] = s.low_health_alarm;
        m[0xc02a] = s.channel5_sound_id;
        memcpy(m + 0xff10, s.audio1_registers, 5);
    }
    /* AudioX_UpdateMusic's loop must resume at .nextChannel, not restart
     * at channel zero after the proof-domain ApplyMusicAffects boundary. */
    for (unsigned channel = 0; channel < 8; ++channel) {
        if (!m[0xc026 + channel]) continue;
        if (channel < 4 && m[0xc002]) {
            if (!(m[0xc002] & 0x80)) {
                m[0xc002] |= 0x80; m[0xff25] = 0; m[0xff1a] = 0x80;
            }
            continue;
        }
        struct cpu_register_state r = {0};
        r.c = (uint8_t)channel;
        uint8_t saved_a = 0, saved_f = 0;
        unsigned next = AUDIO_CONTINUE_APPLY_MUSIC_AFFECTS;
        unsigned budget = 4096;
        while (next != AUDIO_CONTINUE_RETURN && budget--)
            next = audio_dispatch(m, bank, next, &r, &saved_a, &saved_f);
        if (next != AUDIO_CONTINUE_RETURN) {
            fprintf(stderr, "audio: non-terminating command chain bank=%02x channel=%u pc=%04x\n",
                bank, channel, audio_word(m, 0xc006 + 2 * channel));
            m[0xc026 + channel] = 0;
        }
    }
    /* TODO(proof): compare composed per-frame NRxx traces against SM83,
     * including SFX suppression while a home PlaySound fade is pending. */
}
