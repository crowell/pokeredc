#include "port_state.h"

#define ROUTE_17 0x1c
#define PAD_UP_LEFT_RIGHT 0x70

void port_advance_player_sprite(
	struct advance_player_sprite_state *, port_u8 *);

static void
bike_and(struct cpu_register_state *registers, port_u8 right)
{
	registers->a &= right;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
bike_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of DoBikeSpeedup in home/overworld.asm. */
__attribute__((noinline, used)) void
port_do_bike_speedup(struct do_bike_speedup_state *state, port_u8 *memory)
{
	state->advance.registers.a =
	    state->npc_movement_script_pointer_table_num;
	bike_and(&state->advance.registers, state->advance.registers.a);
	if (state->advance.registers.a != 0)
		return;

	state->advance.registers.a = state->cur_map;
	bike_cp(&state->advance.registers, ROUTE_17);
	if (state->advance.registers.a != ROUTE_17) {
		port_advance_player_sprite(&state->advance, memory);
		return;
	}

	state->advance.registers.a = state->joy_held;
	bike_and(&state->advance.registers, PAD_UP_LEFT_RIGHT);
	if (state->advance.registers.a != 0)
		return;
	port_advance_player_sprite(&state->advance, memory);
}
