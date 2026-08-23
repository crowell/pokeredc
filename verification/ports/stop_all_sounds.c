#include "port_state.h"

void port_play_sound(struct play_sound_state *state);

/* Port of StopAllSounds in home/init.asm. */
__attribute__((noinline, used)) void
port_stop_all_sounds(struct play_sound_state *state)
{
	state->registers.a = 2;
	state->audio_rom_bank = state->registers.a;
	state->audio_saved_rom_bank = state->registers.a;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->fade_control = state->registers.a;
	state->new_sound_id = state->registers.a;
	state->last_music_sound_id = state->registers.a;

	state->registers.a--;
	state->registers.f = PORT_FLAG_N | PORT_FLAG_H;
	port_play_sound(state);
}
