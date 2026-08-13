#include "port_state.h"

static port_u16
tree_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
tree_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
tree_cp(struct cpu_register_state *registers, port_u8 right)
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

static void
tree_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	unsigned int wide = (unsigned int)left + right;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
tree_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = tree_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_replace_tree_tile_block_setup(struct replace_tree_block_state *state)
{
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 direction;
	port_u16 stride;

	state->registers.a = state->map_width;
	tree_add_a(&state->registers, 6);
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	state->registers.d = 0;
	state->registers.h = 0xd3;
	state->registers.l = 0x5f;
	state->registers.a = state->map_pointer_low;
	state->registers.h = state->map_pointer_high;
	state->registers.l = state->registers.a;
	stride = tree_pair(state->registers.b, state->registers.c);
	tree_add_hl(&state->registers, stride);
	state->registers.a = state->facing;
	direction = state->registers.a;
	tree_and_a(&state->registers);
	if (direction == 0) {
		state->registers.a = state->y_block;
		tree_and_a(&state->registers);
		if (state->registers.a != 0)
			tree_add_hl(&state->registers, stride);
		tree_add_hl(&state->registers, stride);
		state->registers.e = 2;
		tree_add_hl(&state->registers, 2);
	} else {
		tree_cp(&state->registers, 4);
		if (direction == 4) {
			state->registers.a = state->y_block;
			tree_and_a(&state->registers);
			if (state->registers.a != 0)
				tree_add_hl(&state->registers, stride);
			state->registers.e = 2;
			tree_add_hl(&state->registers, 2);
		} else {
			tree_cp(&state->registers, 8);
			if (direction == 8) {
				state->registers.a = state->x_block;
				tree_and_a(&state->registers);
				if (state->registers.a == 0) {
					state->registers.e = 1;
					tree_add_hl(&state->registers, stride);
					tree_add_hl(&state->registers, 1);
				} else {
					tree_add_hl(&state->registers, stride);
					state->registers.e = 2;
					tree_add_hl(&state->registers, 2);
				}
			} else {
				state->registers.a = state->x_block;
				tree_and_a(&state->registers);
				tree_add_hl(&state->registers, stride);
				state->registers.e = state->registers.a == 0 ? 2 : 3;
				tree_add_hl(&state->registers,
					state->registers.e);
			}
		}
	}
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.a = state->target_tile;
	state->registers.c = state->registers.a;
	return 1;
}

/* Returns 1 to scan again, 0 at the sentinel, or 2 after replacement. */
__attribute__((noinline, used)) port_u8
port_replace_tree_tile_block_scan_step(struct replace_tree_block_state *state)
{
	port_u16 de = tree_pair(state->registers.d, state->registers.e);

	state->registers.a = state->fetched_match;
	de += 2;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	tree_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 0;
	tree_cp(&state->registers, state->registers.c);
	if (state->registers.a != state->registers.c)
		return 1;
	de--;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = state->replacement;
	state->written = state->registers.a;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	state->target_tile = state->registers.a;
	return 2;
}

/* Port of ReplaceTreeTileBlock in engine/overworld/cut.asm. */
__attribute__((noinline, used)) void
port_replace_tree_tile_block(struct replace_tree_block_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_replace_tree_tile_block_setup(state);
	port_u16 address;

	while (continuation == 1) {
		address = tree_pair(state->registers.d, state->registers.e);
		state->fetched_match = memory[address];
		state->replacement = memory[(port_u16)(address + 1)];
		continuation = port_replace_tree_tile_block_scan_step(state);
	}
	if (continuation == 2) {
		address = tree_pair(state->write_h, state->write_l);
		memory[address] = state->written;
	}
}
