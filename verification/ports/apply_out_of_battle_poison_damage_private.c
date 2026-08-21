#include "port_state.h"

struct apply_poison_private_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
	port_u8 party_count;
	port_u8 step_counter;
};

/* Port of ApplyOutOfBattlePoisonDamage through the step-frequency guard. */
__attribute__((noinline, used)) void
port_apply_out_of_battle_poison_damage_private(
	struct apply_poison_private_state *state)
{
	if ((state->status_flags5 & 0x80) != 0)
		state->registers.a = (port_u8)(state->status_flags5 << 1);
	else if (state->party_count == 0)
		state->registers.a = 0;
	else
		state->registers.a = (port_u8)(state->step_counter & 3);
}
