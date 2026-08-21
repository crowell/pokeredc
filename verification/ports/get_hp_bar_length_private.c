#include "port_state.h"

struct get_hp_bar_length_private_state {
	struct cpu_register_state registers;
	port_u8 multiplicand0;
	port_u8 multiplicand1;
	port_u8 multiplicand2;
	port_u8 multiplicand3;
};

/* Port of GetHPBarLength through Multiply setup. */
__attribute__((noinline, used)) void
port_get_hp_bar_length_private(struct get_hp_bar_length_private_state *state)
{
	state->registers.a = 0x30;
	state->registers.h = 0xff;
	state->registers.l = 0x99;
	state->multiplicand0 = 0;
	state->multiplicand1 = state->registers.b;
	state->multiplicand2 = state->registers.c;
	state->multiplicand3 = 0x30;
}
