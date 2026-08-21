#include "port_state.h"

struct enemy_fly_charge_state {
	struct cpu_register_state registers;
	port_u8 move_effect;
};

/* Port of EnemyCheckIfFlyOrChargeEffect through the FLY comparison. */
__attribute__((noinline, used)) void
port_enemy_check_if_fly_or_charge_effect(struct enemy_fly_charge_state *state)
{
	port_u8 value = state->move_effect;
	state->registers.a = value;
	state->registers.f = (port_u8)(PORT_FLAG_N |
		((port_u8)((value & 0x0f) < 0x0b) * PORT_FLAG_H) |
		((port_u8)(value < 0x2b) * PORT_FLAG_C) |
		((port_u8)(value == 0x2b) * PORT_FLAG_Z));
}
