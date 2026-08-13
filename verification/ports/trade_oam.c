#include "port_state.h"

__attribute__((noinline, used)) void
port_trade_add_offsets_to_oam_coords_begin(struct trade_oam_step_state *state)
{
	state->registers.h = 0xc3;
	state->registers.l = 0x00;
	state->registers.c = 20;
}

__attribute__((noinline, used)) port_u8
port_trade_add_offsets_to_oam_coords_step(struct trade_oam_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 wide;
	port_u8 old_c = state->registers.c;
	port_u8 carry;

	state->registers.a = state->base_y;
	state->registers.a = (port_u8)(state->registers.a + state->y);
	state->y = state->registers.a;
	hl++;
	state->registers.a = state->base_x;
	wide = (port_u16)state->registers.a + state->x;
	state->registers.a = (port_u8)wide;
	carry = wide > 0xff;
	state->x = state->registers.a;
	hl = (port_u16)(hl + 3);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	state->registers.f = PORT_FLAG_N;
	if (carry)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of Trade_AddOffsetsToOAMCoords in engine/movie/trade.asm. */
__attribute__((noinline, used)) void
port_trade_add_offsets_to_oam_coords(struct trade_oam_state *state)
{
	struct trade_oam_step_state step;
	port_u8 index;

	step.registers = state->registers;
	step.base_y = state->base_y;
	step.base_x = state->base_x;
	port_trade_add_offsets_to_oam_coords_begin(&step);
	for (index = 0; index < 20; index++) {
		step.y = state->oam[index * 4];
		step.x = state->oam[index * 4 + 1];
		port_trade_add_offsets_to_oam_coords_step(&step);
		state->oam[index * 4] = step.y;
		state->oam[index * 4 + 1] = step.x;
	}
	state->registers = step.registers;
}
