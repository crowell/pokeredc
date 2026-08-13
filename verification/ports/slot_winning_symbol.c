#include "port_state.h"

/* Port of SlotMachine_PrintWinningSymbol in engine/slots/slot_machine.asm. */
__attribute__((noinline, used)) void
port_slot_machine_print_winning_symbol(
	struct slot_winning_symbol_state *state)
{
	port_u8 value;

	state->registers.h = 0xc4;
	state->registers.l = 0xba;
	state->registers.a = state->winning_symbol;
	value = (port_u8)(state->registers.a + 0x25);
	state->registers.a = value;
	state->writes[0] = state->registers.a;
	state->registers.l++;
	state->registers.a++;
	state->writes[1] = state->registers.a;
	state->registers.l--;
	state->registers.a++;
	state->registers.d = 0xff;
	state->registers.e = 0xec;
	state->registers.h = 0xc4;
	state->registers.l = 0xa6;
	state->writes[2] = state->registers.a;
	state->registers.l++;
	state->registers.a++;
	state->writes[3] = state->registers.a;
	state->registers.h = 0xc4;
	state->registers.l = 0xf2;
	state->writes[4] = 0xee;
	state->registers.f = PORT_FLAG_C;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->winning_symbol & 0x0f) == 8)
		state->registers.f |= PORT_FLAG_H;
}
