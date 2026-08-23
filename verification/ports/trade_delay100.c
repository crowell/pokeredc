#include "port_state.h"

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

/* Port of Trade_Delay100 in engine/link/trade.asm. */
__attribute__((noinline, used)) void
port_trade_delay100(struct trade_delay_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	state->registers.c = 0x64;
	state->frames_waited = state->registers.c;
	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
}
