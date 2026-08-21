#include "port_state.h"

struct trade_center_draw_cancel_box_private_state {
	struct cpu_register_state registers;
};

/* Port of TradeCenter_DrawCancelBox through FillMemory entry. */
__attribute__((noinline, used)) void
port_trade_center_draw_cancel_box_private(
	struct trade_center_draw_cancel_box_private_state *state)
{
	state->registers.h = 0xc4;
	state->registers.l = 0xd7;
	state->registers.a = 0x7e;
	state->registers.b = 0;
	state->registers.c = 0x31;
}
