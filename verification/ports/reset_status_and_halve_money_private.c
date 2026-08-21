#include "port_state.h"

struct reset_blackout_private_state {
	struct cpu_register_state registers;
	port_u8 battle_result;
	port_u8 walk_bike_surf;
	port_u8 in_battle;
	port_u8 map_pal_offset;
	port_u8 npc_function;
	port_u8 joy_held;
	port_u8 npc_pointer_table;
	port_u8 misc_flags;
	port_u8 money0;
	port_u8 money1;
	port_u8 money2;
};

/* Port of ResetStatusAndHalveMoneyOnBlackout through HasEnoughMoney. */
__attribute__((noinline, used)) void
port_reset_status_and_halve_money_private(
	struct reset_blackout_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = 0;
	state->battle_result = 0;
	state->walk_bike_surf = 0;
	state->in_battle = 0;
	state->map_pal_offset = 0;
	state->npc_function = 0;
	state->joy_held = 0;
	state->npc_pointer_table = 0;
	state->misc_flags = 0;
	state->money0 = 0;
	state->money1 = 0;
	state->money2 = 0;
}
