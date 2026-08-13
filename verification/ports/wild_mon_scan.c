#include "port_state.h"

static void
map_mon_compare(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_check_map_for_mon_begin(struct map_mon_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = 10;
}

__attribute__((noinline, used)) port_u8
port_check_map_for_mon_step(struct map_mon_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_b = state->registers.b;

	state->matched = 0;
	state->registers.a = state->pokedex_num;
	map_mon_compare(&state->registers, state->fetched);
	if (state->registers.a == state->fetched) {
		state->registers.a = state->registers.c;
		state->written = state->registers.a;
		state->matched = 1;
		de++;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
	}
	hl = (port_u16)(hl + 2);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.b == 0;
}

__attribute__((noinline, used)) void
port_check_map_for_mon_finish(struct map_mon_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Port of CheckMapForMon in engine/items/item_effects.asm. */
__attribute__((noinline, used)) void
port_check_map_for_mon(struct map_mon_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	port_check_map_for_mon_begin(state);
	do {
		source = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		destination = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched = memory[source];
		port_check_map_for_mon_step(state);
		if (state->matched)
			memory[destination] = state->written;
	} while (state->registers.b != 0);
	port_check_map_for_mon_finish(state);
}
