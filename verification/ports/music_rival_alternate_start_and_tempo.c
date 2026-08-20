#include "port_state.h"

struct music_rival_alternate_start_state {
    struct cpu_register_state registers;
    port_u16 channel1_pointer;
    port_u16 channel2_pointer;
    port_u16 channel3_pointer;
    port_u8 sound_id;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 fade_out_control;
    port_u8 play_music_called;
};

__attribute__((noinline, used)) void
port_music_rival_alternate_start(struct music_rival_alternate_start_state *state);

#define RIVAL_CH1_ALTERNATE_START_AND_TEMPO 0x719bu
#define CHANNEL_POINTER_END 0xc008u

/* Port of Music_RivalAlternateStartAndTempo in audio/alternate_tempo.asm. */
__attribute__((noinline, used)) void
port_music_rival_alternate_start_and_tempo(
    struct music_rival_alternate_start_state *state)
{
    port_music_rival_alternate_start(state);
    state->channel1_pointer = RIVAL_CH1_ALTERNATE_START_AND_TEMPO;
    state->registers.h = (port_u8)(CHANNEL_POINTER_END >> 8);
    state->registers.l = (port_u8)CHANNEL_POINTER_END;
}
