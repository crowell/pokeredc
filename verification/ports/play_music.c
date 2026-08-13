#include "port_state.h"

__attribute__((noinline, used)) void
port_play_music_begin(struct play_music_state *state)
{
	state->registers.b = state->registers.a;
	state->new_sound_id = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->fade_out_control = 0;
	state->registers.a = state->registers.c;
	state->audio_rom_bank = state->registers.a;
	state->saved_audio_rom_bank = state->registers.a;
	state->registers.a = state->registers.b;
	state->dispatched = 1;
}

/* Port of PlayMusic in home/audio.asm. */
__attribute__((noinline, used)) void
port_play_music(struct play_music_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[4])
{
	port_play_music_begin(state);
	/* The fallthrough into PlaySound is an explicit continuation boundary. */
	state->registers = *callback_registers;
	state->new_sound_id = callback_globals[0];
	state->fade_out_control = callback_globals[1];
	state->audio_rom_bank = callback_globals[2];
	state->saved_audio_rom_bank = callback_globals[3];
}
