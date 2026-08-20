#include "port_state.h"

struct soft_reset_state {
    struct cpu_register_state registers;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 fade_out_control;
    port_u8 new_sound_id;
    port_u8 last_music_sound_id;
    port_u8 stop_all_sounds_called;
    port_u8 palette_whiteout_called;
    port_u8 delay_frames_requested;
    port_u8 delay_frames_called;
};

/* Port of SoftReset in home/init.asm. StopAllSounds, GBPalWhiteOut, and
 * DelayFrames are represented by explicit call-boundary state; Init remains
 * the following routine at the assembly fallthrough boundary. */
__attribute__((noinline, used)) void
port_soft_reset(struct soft_reset_state *state)
{
    state->audio_rom_bank = 2;
    state->audio_saved_bank = 2;
    state->fade_out_control = 0;
    state->new_sound_id = 0;
    state->last_music_sound_id = 0;
    state->stop_all_sounds_called = 1;
    state->palette_whiteout_called = 1;
    state->delay_frames_requested = 32;
    state->delay_frames_called = 1;
}
