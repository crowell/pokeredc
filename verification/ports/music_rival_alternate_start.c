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

#define BANK_MUSIC_MEET_RIVAL 0x02u
#define MUSIC_MEET_RIVAL 0xdeu
#define RIVAL_CH1_ALTERNATE_START 0x71a2u
#define RIVAL_CH2_ALTERNATE_START 0x721du
#define RIVAL_CH3_ALTERNATE_START 0x72b5u
#define CHANNEL_POINTER_END 0xc00cu

/* Port of Music_RivalAlternateStart in audio/alternate_tempo.asm. */
__attribute__((noinline, used)) void
port_music_rival_alternate_start(struct music_rival_alternate_start_state *state)
{
    state->registers.c = BANK_MUSIC_MEET_RIVAL;
    state->registers.a = MUSIC_MEET_RIVAL;
    state->sound_id = MUSIC_MEET_RIVAL;
    state->fade_out_control = 0;
    state->audio_rom_bank = BANK_MUSIC_MEET_RIVAL;
    state->audio_saved_bank = BANK_MUSIC_MEET_RIVAL;
    state->play_music_called = 1;
    state->channel1_pointer = RIVAL_CH1_ALTERNATE_START;
    state->channel2_pointer = RIVAL_CH2_ALTERNATE_START;
    state->channel3_pointer = RIVAL_CH3_ALTERNATE_START;
    state->registers.h = (port_u8)(CHANNEL_POINTER_END >> 8);
    state->registers.l = (port_u8)CHANNEL_POINTER_END;
}
