#include "port_state.h"

void port_far_copy_data2(struct far_copy_data2_state *state,
	port_u8 *memory);

__attribute__((noinline, used)) void
port_load_tileset_tile_pattern_data(
	struct load_tileset_tile_pattern_data_state *state, port_u8 *memory)
{
	state->copy.registers.a = state->tileset_gfx_low;
	state->copy.registers.l = state->copy.registers.a;
	state->copy.registers.a = state->tileset_gfx_high;
	state->copy.registers.h = state->copy.registers.a;
	state->copy.registers.d = 0x90;
	state->copy.registers.e = 0;
	state->copy.registers.b = 6;
	state->copy.registers.c = 0;
	state->copy.registers.a = state->tileset_bank;
	port_far_copy_data2(&state->copy, memory);
}
