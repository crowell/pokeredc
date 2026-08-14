#include "port_state.h"

/* Port of HoFFadeOutScreenAndMusic in engine/movie/hall_of_fame.asm.
 *
 * Writes the audio-fade control bytes (wAudioFadeOutControl = $ff, and both
 * wAudioFadeOutCounterReloadValue / wAudioFadeOutCounter = 10) then transfers
 * control to GBFadeOutToWhite; the port isolates the setup stores and returns.
 */

#define HOF_W_AUDIO_FADE_OUT_CONTROL 0xcfc7u
#define HOF_W_AUDIO_FADE_OUT_COUNTER_RELOAD 0xcfc8u
#define HOF_W_AUDIO_FADE_OUT_COUNTER 0xcfc9u

__attribute__((noinline, used)) void
port_ho_f_fade_out_screen_and_music(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->a = 0x0au;
	memory[HOF_W_AUDIO_FADE_OUT_COUNTER_RELOAD] = state->a;
	memory[HOF_W_AUDIO_FADE_OUT_COUNTER] = state->a;
	state->a = 0xffu;
	memory[HOF_W_AUDIO_FADE_OUT_CONTROL] = state->a;
}
