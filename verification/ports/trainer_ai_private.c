#include "port_state.h"

struct trainer_ai_private_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

/* Port of TrainerAI through the initial wIsInBattle decrement/check. */
__attribute__((noinline, used)) void
port_trainer_ai_private(struct trainer_ai_private_state *state)
{
	port_u8 old_value = state->is_in_battle;
	port_u8 result = (port_u8)(old_value - 1);
	state->registers.a = result;
	state->registers.f = 0;
}
