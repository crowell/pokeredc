#include "port_state.h"

/* Port of DeterminePaletteID in engine/gfx/palettes.asm. */
__attribute__((noinline, used)) void
port_determine_palette_id(struct determine_palette_id_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_pokedex_num)
{
	port_u8 saved_b;
	port_u8 saved_c;
	port_u16 hl;
	port_u16 de;
	port_u16 next;

	state->dispatched = 0;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->registers.a & 0x08) == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = 0x19;
	if ((state->registers.f & PORT_FLAG_Z) == 0)
		return;
	state->registers.a = state->fetched_species;
	state->pokedex_num = state->registers.a;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0) {
		saved_b = state->registers.b;
		saved_c = state->registers.c;
		state->registers.a = 0x3a;
		state->registers = *callback_registers;
		state->pokedex_num = *callback_pokedex_num;
		state->registers.b = saved_b;
		state->registers.c = saved_c;
		state->dispatched = 1;
		state->registers.a = state->pokedex_num;
	}
	state->registers.e = state->registers.a;
	state->registers.d = 0;
	state->registers.h = 0x65;
	state->registers.l = 0xc8;
	hl = 0x65c8;
	de = state->registers.e;
	next = (port_u16)(hl + de);
	state->registers.f &= PORT_FLAG_Z;
	state->registers.h = (port_u8)(next >> 8);
	state->registers.l = (port_u8)next;
	state->registers.a = state->fetched_palette;
}
