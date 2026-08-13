#include "port_state.h"

/* Port of Trade_AnimCircledMon in engine/movie/trade.asm. */
__attribute__((noinline, used)) void
port_trade_anim_circled_mon(struct trade_circled_mon_state *state)
{
	port_u8 index;
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;

	state->registers.a = state->background_palette;
	state->registers.a ^= 0x3c;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->background_palette = state->registers.a;
	state->registers.h = 0xc3;
	state->registers.l = 0x02;
	state->registers.d = 0;
	state->registers.e = 4;
	state->registers.c = 20;
	for (index = 0; index < 20; index++) {
		state->registers.a = state->tile_ids[index];
		state->registers.a ^= 0x40;
		state->tile_ids[index] = state->registers.a;
		state->registers.c--;
	}
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
