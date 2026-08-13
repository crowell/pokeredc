#include "port_state.h"

static port_u16
tile_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
tile_pair_cp(struct cpu_register_state *registers, port_u8 right)
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

__attribute__((noinline, used)) port_u8
port_check_tile_pair_collisions_setup(struct tile_pair_collision_state *state)
{
	state->registers.a = state->front_tile;
	state->registers.c = state->registers.a;
	return 1;
}

/* Returns 1 to scan again, 2 for a collision, or 0 at the terminator. */
__attribute__((noinline, used)) port_u8
port_check_tile_pair_collisions_step(struct tile_pair_collision_state *state)
{
	port_u16 hl = tile_pair(state->registers.h, state->registers.l);

	state->registers.a = state->current_tileset;
	state->registers.b = state->registers.a;
	state->registers.a = state->entry_tileset;
	hl++;
	tile_pair_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.f = PORT_FLAG_H;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	tile_pair_cp(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b) {
		hl += 2;
		goto retry;
	}
	state->registers.a = state->standing_tile;
	state->registers.b = state->registers.a;
	state->registers.a = state->first_tile;
	tile_pair_cp(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b) {
		hl++;
		state->registers.a = state->second_tile;
		tile_pair_cp(&state->registers, state->registers.c);
		if (state->registers.a == state->registers.c)
			goto found;
		goto retry;
	}
	hl++;
	state->registers.a = state->second_tile;
	tile_pair_cp(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b) {
		hl++;
		goto retry;
	}
	hl--;
	state->registers.a = state->first_tile;
	hl++;
	tile_pair_cp(&state->registers, state->registers.c);
	hl++;
	if (state->registers.a == state->registers.c)
		goto found;
retry:
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 1;
found:
	state->registers.f = (state->registers.f & PORT_FLAG_Z) | PORT_FLAG_C;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 2;
}

/* Port of CheckForTilePairCollisions in home/overworld.asm. */
__attribute__((noinline, used)) void
port_check_for_tile_pair_collisions(
	struct tile_pair_collision_state *state, const port_u8 *memory)
{
	port_u8 continuation = port_check_tile_pair_collisions_setup(state);
	port_u16 hl;

	while (continuation == 1) {
		hl = tile_pair(state->registers.h, state->registers.l);
		state->entry_tileset = memory[hl];
		state->first_tile = memory[(port_u16)(hl + 1)];
		state->second_tile = memory[(port_u16)(hl + 2)];
		continuation = port_check_tile_pair_collisions_step(state);
	}
}
