#include "port_state.h"

/* Port of DivideBCD_divDivisorBy10 in engine/math/bcd.asm. */
__attribute__((noinline, used)) void
port_divide_bcd_div_divisor_by10(struct divide_bcd_by10_state *state)
{
	port_u8 high = (port_u8)(state->divisor[0] >> 4);
	port_u8 middle_high = (port_u8)(state->divisor[1] >> 4);
	port_u8 low_high = (port_u8)(state->divisor[2] >> 4);

	state->divisor[2] = (port_u8)((state->divisor[1] << 4) | low_high);
	state->divisor[1] = (port_u8)((state->divisor[0] << 4) | middle_high);
	state->divisor[0] = high;
	state->registers.b = middle_high;
	state->registers.a = high;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
