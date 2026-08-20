#include "port_state.h"

struct music_cities1_alternate_tempo_state {
    struct cpu_register_state registers;
    port_u16 channel1_pointer;
    port_u8 fade_counter_reload;
    port_u8 fade_counter;
    port_u8 fade_control;
    port_u8 delay_frames_requested;
    port_u8 delay_called;
    port_u8 sound_id;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 play_music_called;
};

#define BANK_MUSIC_CITIES1 0x02u
#define MUSIC_CITIES1 0xc3u
#define CITIES1_CH1_ALTERNATE_TEMPO 0x6a6fu
#define CHANNEL_POINTER_END 0xc008u

/* Port of Music_Cities1AlternateTempo in audio/alternate_tempo.asm. */
__attribute__((noinline, used)) void
port_music_cities1_alternate_tempo(
    struct music_cities1_alternate_tempo_state *state)
{
    state->fade_counter_reload = 10;
    state->fade_counter = 10;
    state->fade_control = 0xff;
    state->delay_frames_requested = 100;
    state->delay_called = 1;
    state->registers.c = BANK_MUSIC_CITIES1;
    state->registers.a = MUSIC_CITIES1;
    state->sound_id = MUSIC_CITIES1;
    state->fade_control = 0;
    state->audio_rom_bank = BANK_MUSIC_CITIES1;
    state->audio_saved_bank = BANK_MUSIC_CITIES1;
    state->play_music_called = 1;
    state->channel1_pointer = CITIES1_CH1_ALTERNATE_TEMPO;
    state->registers.a = (port_u8)(CITIES1_CH1_ALTERNATE_TEMPO >> 8);
    state->registers.h = (port_u8)(CHANNEL_POINTER_END >> 8);
    state->registers.l = (port_u8)CHANNEL_POINTER_END;
}
