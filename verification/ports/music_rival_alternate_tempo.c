#include "port_state.h"

struct music_rival_alternate_tempo_state {
    struct cpu_register_state registers;
    port_u16 channel1_pointer;
    port_u8 sound_id;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 fade_out_control;
    port_u8 play_music_called;
};

#define BANK_MUSIC_MEET_RIVAL 0x02u
#define MUSIC_MEET_RIVAL 0xdeu
#define RIVAL_CH1_ALTERNATE_TEMPO 0x7119u
#define CHANNEL_POINTER_END 0xc008u

/* Port of Music_RivalAlternateTempo in audio/alternate_tempo.asm. */
__attribute__((noinline, used)) void
port_music_rival_alternate_tempo(struct music_rival_alternate_tempo_state *state)
{
    state->registers.c = BANK_MUSIC_MEET_RIVAL;
    state->registers.a = MUSIC_MEET_RIVAL;
    state->sound_id = MUSIC_MEET_RIVAL;
    state->audio_rom_bank = BANK_MUSIC_MEET_RIVAL;
    state->audio_saved_bank = BANK_MUSIC_MEET_RIVAL;
    state->fade_out_control = 0;
    state->play_music_called = 1;
    state->channel1_pointer = RIVAL_CH1_ALTERNATE_TEMPO;
    state->registers.h = (port_u8)(CHANNEL_POINTER_END >> 8);
    state->registers.l = (port_u8)CHANNEL_POINTER_END;
}
