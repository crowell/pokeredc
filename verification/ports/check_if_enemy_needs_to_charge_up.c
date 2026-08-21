#include "port_state.h"

struct enemy_charge_check_state {
	struct cpu_register_state registers;
	port_u8 move_effect;
};

/* Port of CheckIfEnemyNeedsToChargeUp through the CHARGE comparison. */
__attribute__((noinline, used)) void
port_check_if_enemy_needs_to_charge_up(struct enemy_charge_check_state *state)
{
	port_u8 value = state->move_effect;
	state->registers.a = value;
	state->registers.f = (port_u8)(PORT_FLAG_N |
		((port_u8)((value & 0x0f) < 0x07) * PORT_FLAG_H) |
		((port_u8)(value < 0x27) * PORT_FLAG_C) |
		((port_u8)(value == 0x27) * PORT_FLAG_Z));
}
