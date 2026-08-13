#include "port_state.h"

__attribute__((noinline, used)) void
port_check_for_tile_pair_collisions2_begin(struct tile_pair_entry_state *state)
{
	state->registers.a = state->fetched_tile;
	state->standing_tile = state->registers.a;
	state->dispatched = 1;
}

/* Port of CheckForTilePairCollisions2 in home/overworld.asm. */
__attribute__((noinline, used)) void
port_check_for_tile_pair_collisions2(struct tile_pair_entry_state *state,
	const struct cpu_register_state *callback_registers,
	port_u8 callback_standing_tile)
{
	port_check_for_tile_pair_collisions2_begin(state);
	state->registers = *callback_registers;
	state->standing_tile = callback_standing_tile;
}

static void
compare_200(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 result = (port_u8)(value - 200);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 8)
		registers->f |= PORT_FLAG_H;
	if (value < 200)
		registers->f |= PORT_FLAG_C;
}

static __attribute__((noinline)) void
store_trainer_number(struct battle_enemy_parameters_state *state)
{
	state->trainer_number = state->registers.a;
}

static __attribute__((noinline)) void
store_enemy_level(struct battle_enemy_parameters_state *state)
{
	state->enemy_level = state->registers.a;
}

/* Port of InitBattleEnemyParameters in home/trainers.asm. */
__attribute__((noinline, used)) void
port_init_battle_enemy_parameters(struct battle_enemy_parameters_state *state)
{
	state->registers.a = state->engaged_class;
	state->current_opponent = state->registers.a;
	state->enemy_class = state->registers.a;
	compare_200(&state->registers, state->registers.a);
	state->registers.a = state->engaged_set;
	if (state->engaged_class < 200)
		store_enemy_level(state);
	else
		store_trainer_number(state);
}
