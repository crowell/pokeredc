#include "port_state.h"

/* Port of CompareMapMusicBankWithCurrentBank in home/audio.asm. */
__attribute__((noinline, used)) void
port_compare_map_music_bank_with_current_bank(struct music_bank_state *state)
{
	state->registers.a = state->map_bank;
	state->registers.e = state->registers.a;
	state->registers.a = state->audio_bank;
	if (state->registers.a == state->registers.e) {
		state->saved_bank = state->registers.a;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		return;
	}
	state->registers.a = state->registers.c;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->registers.e;
	if (state->registers.c == 0)
		state->audio_bank = state->registers.a;
	state->saved_bank = state->registers.a;
	state->registers.f = (state->registers.f & PORT_FLAG_Z) | PORT_FLAG_C;
}
