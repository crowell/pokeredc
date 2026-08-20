#include "port_state.h"

struct print_beginning_battle_text_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

/* Port of the PrintBeginningBattleText entry through its trainer/wild branch. */
__attribute__((noinline, used)) void
port_print_beginning_battle_text(struct print_beginning_battle_text_state *state)
{
	port_u8 old = state->is_in_battle;
	port_u8 result = (port_u8)(old - 1);

	state->registers.a = result;
	state->registers.f = state->registers.f & PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
}
