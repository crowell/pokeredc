#include "port_state.h"

static void
load_mansion_block(struct mansion_block_loader_state *state, port_u8 block,
	const struct cpu_register_state *callback_registers,
	port_u8 callback_block)
{
	state->registers.a = block;
	state->new_tile_block_id = state->registers.a;
	state->registers.a = 0x17;
	state->dispatched = 1;
	/* Predef ReplaceTileBlock is an arbitrary continuation boundary. */
	state->registers = *callback_registers;
	state->new_tile_block_id = callback_block;
}

/* Port of Mansion1LoadHorizontalGateBlock in scripts/PokemonMansion1F.asm. */
__attribute__((noinline, used)) void
port_mansion1_load_horizontal_gate_block(
	struct mansion_block_loader_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_block)
{
	load_mansion_block(state, 0x2d, callback_registers, *callback_block);
}

/* Port of Mansion1LoadEmptyFloorTileBlock in scripts/PokemonMansion1F.asm. */
__attribute__((noinline, used)) void
port_mansion1_load_empty_floor_tile_block(
	struct mansion_block_loader_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 *callback_block)
{
	load_mansion_block(state, 0x0e, callback_registers, *callback_block);
}
