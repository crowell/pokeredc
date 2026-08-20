#include "port_state.h"

struct inward_spiral_step_state {
	struct cpu_register_state registers;
	port_u8 update_screen_counter;
	port_u8 written;
};

/* Port of the first BattleTransition_InwardSpiral_ iteration through the
 * BattleTransition_TransferDelay3 call boundary. */
__attribute__((noinline, used)) void
port_battle_transition_inward_spiral_step(struct inward_spiral_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
	    state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
	    state->registers.e);
	unsigned int wide = (unsigned int)hl + de;
	port_u8 old_counter = state->update_screen_counter;
	port_u8 result = (port_u8)(old_counter - 1);

	state->written = 0xff;
	state->registers.h = (port_u8)(wide >> 8);
	state->registers.l = (port_u8)wide;
	state->registers.a = result;
	state->registers.f = (wide > 0xffff) ? PORT_FLAG_C : 0;
	state->registers.f |= PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_counter & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
}
