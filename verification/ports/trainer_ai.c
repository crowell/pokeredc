#include "port_state.h"

/* Port of GenericAI in engine/battle/trainer_ai.asm. */
__attribute__((noinline, used)) void
port_generic_ai(struct cpu_register_state *state)
{
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}

/* Port of DecrementAICount in engine/battle/trainer_ai.asm. */
__attribute__((noinline, used)) void
port_decrement_ai_count(struct ai_count_state *state)
{
	state->registers.h = 0xcc;
	state->registers.l = 0xdf;
	state->ai_count--;
	state->registers.f = PORT_FLAG_C;
	if (state->ai_count == 0)
		state->registers.f |= PORT_FLAG_Z;
}
