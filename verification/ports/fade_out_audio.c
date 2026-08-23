#include "port_state.h"

void port_play_sound(struct play_sound_state *state);

static void
and_a_flags(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
dec_a(struct cpu_register_state *registers)
{
	port_u8 before = registers->a;
	port_u8 flags = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_N);
	registers->a--;
	if (registers->a == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	registers->f = flags;
}

static void
swap_a(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) | (registers->a >> 4));
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

__attribute__((noinline, used)) void
port_fade_out_audio(struct fade_out_audio_state *state)
{
	struct play_sound_state *sound = &state->sound;
	struct cpu_register_state *registers = &sound->registers;

	registers->a = sound->fade_control;
	and_a_flags(registers);
	if (registers->a == 0) {
		registers->a = state->status_flags2;
		registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_H);
		if ((registers->a & 2) == 0)
			registers->f |= PORT_FLAG_Z;
		if ((registers->f & PORT_FLAG_Z) == 0)
			return;
		registers->a = 0x77;
		state->audio_volume = registers->a;
		return;
	}

	registers->a = sound->fade_counter;
	and_a_flags(registers);
	if (registers->a != 0) {
		dec_a(registers);
		sound->fade_counter = registers->a;
		return;
	}

	registers->a = sound->fade_reload;
	sound->fade_counter = registers->a;
	registers->a = state->audio_volume;
	and_a_flags(registers);
	if (registers->a != 0) {
		registers->b = registers->a;
		registers->a &= 0x0f;
		and_a_flags(registers);
		dec_a(registers);
		registers->c = registers->a;
		registers->a = registers->b;
		registers->a &= 0xf0;
		and_a_flags(registers);
		swap_a(registers);
		dec_a(registers);
		swap_a(registers);
		registers->a |= registers->c;
		registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
		state->audio_volume = registers->a;
		return;
	}

	registers->a = sound->fade_control;
	registers->b = registers->a;
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	sound->fade_control = registers->a;
	registers->a = 0xff;
	sound->new_sound_id = registers->a;
	port_play_sound(sound);
	registers->a = sound->audio_saved_rom_bank;
	sound->audio_rom_bank = registers->a;
	registers->a = registers->b;
	sound->new_sound_id = registers->a;
	port_play_sound(sound);
}
