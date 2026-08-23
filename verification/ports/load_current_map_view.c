#include "port_state.h"

void port_draw_tile_block(struct draw_tile_block_state *, port_u8 *);

enum {
	SURROUNDING_TILES = 0xc508,
	VISIBLE_TILES = 0xc3a0,
	SCREEN_BLOCK_WIDTH = 6,
	SCREEN_BLOCK_HEIGHT = 5,
	BLOCK_WIDTH = 4,
	SURROUNDING_WIDTH = 24,
	SCREEN_WIDTH = 20,
	SCREEN_HEIGHT = 18,
};

static port_u16
map_view_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
map_view_set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
map_view_dec(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 carry = *flags & PORT_FLAG_C;

	*value = (port_u8)(old - 1);
	*flags = (port_u8)(carry | PORT_FLAG_N);
	if (*value == 0)
		*flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		*flags |= PORT_FLAG_H;
}

static void
map_view_add_a(struct cpu_register_state *registers, port_u8 right)
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
map_view_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = map_view_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;
	port_u8 zero = registers->f & PORT_FLAG_Z;

	map_view_set_pair(&registers->h, &registers->l, (port_u16)wide);
	registers->f = zero;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

static void
map_view_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

__attribute__((noinline, used)) void
port_load_current_map_view_begin(struct load_current_map_view_state *state)
{
	state->registers.a = state->loaded_rom_bank;
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->registers.a = state->tileset_bank;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
	state->registers.a = state->map_view_pointer_low;
	state->registers.e = state->registers.a;
	state->registers.a = state->map_view_pointer_high;
	state->registers.d = state->registers.a;
	state->registers.h = (port_u8)(SURROUNDING_TILES >> 8);
	state->registers.l = (port_u8)SURROUNDING_TILES;
	state->registers.b = SCREEN_BLOCK_HEIGHT;
}

__attribute__((noinline, used)) void
port_load_current_map_view_begin_render_row(
	struct load_current_map_view_state *state)
{
	state->row_h = state->registers.h;
	state->row_l = state->registers.l;
	state->row_d = state->registers.d;
	state->row_e = state->registers.e;
	state->registers.c = SCREEN_BLOCK_WIDTH;
}

/* Returns one while another block remains in the current six-block row. */
__attribute__((noinline, used)) port_u8
port_load_current_map_view_draw_step(
	struct load_current_map_view_state *state,
	struct draw_tile_block_state *draw,
	port_u8 *memory)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;

	state->registers.a = state->fetched_block;
	state->registers.c = state->registers.a;
	draw->registers = state->registers;
	draw->blocks_low = state->tileset_blocks_low;
	draw->blocks_high = state->tileset_blocks_high;
	port_draw_tile_block(draw, memory);
	state->registers = draw->registers;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
	map_view_set_pair(&state->registers.h, &state->registers.l,
	    (port_u16)(map_view_pair(saved_h, saved_l) + BLOCK_WIDTH));
	map_view_set_pair(&state->registers.d, &state->registers.e,
	    (port_u16)(map_view_pair(saved_d, saved_e) + 1));
	map_view_dec(&state->registers.c, &state->registers.f);
	return state->registers.c != 0;
}

/* Returns one while another one of the five block rows remains. */
__attribute__((noinline, used)) port_u8
port_load_current_map_view_next_render_row(
	struct load_current_map_view_state *state)
{
	state->registers.d = state->row_d;
	state->registers.e = state->row_e;
	state->registers.a = state->map_width;
	map_view_add_a(&state->registers, 6);
	map_view_add_a(&state->registers, state->registers.e);
	state->registers.e = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) != 0)
		state->registers.d++;
	state->registers.h = state->row_h;
	state->registers.l = state->row_l;
	state->registers.a = SURROUNDING_WIDTH * BLOCK_WIDTH;
	map_view_add_a(&state->registers, state->registers.l);
	state->registers.l = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) != 0)
		state->registers.h++;
	map_view_dec(&state->registers.b, &state->registers.f);
	return state->registers.b != 0;
}

__attribute__((noinline, used)) void
port_load_current_map_view_prepare_copy(
	struct load_current_map_view_state *state)
{
	state->registers.h = (port_u8)(SURROUNDING_TILES >> 8);
	state->registers.l = (port_u8)SURROUNDING_TILES;
	state->registers.b = 0;
	state->registers.c = 0;
	state->registers.a = state->y_block_coord;
	map_view_and_a(&state->registers);
	if (state->registers.a != 0) {
		state->registers.b = 0;
		state->registers.c = SURROUNDING_WIDTH * 2;
		map_view_add_hl(&state->registers,
		    map_view_pair(state->registers.b, state->registers.c));
	}
	state->registers.a = state->x_block_coord;
	map_view_and_a(&state->registers);
	if (state->registers.a != 0) {
		state->registers.b = 0;
		state->registers.c = BLOCK_WIDTH / 2;
		map_view_add_hl(&state->registers,
		    map_view_pair(state->registers.b, state->registers.c));
	}
	state->registers.d = (port_u8)(VISIBLE_TILES >> 8);
	state->registers.e = (port_u8)VISIBLE_TILES;
	state->registers.b = SCREEN_HEIGHT;
}

__attribute__((noinline, used)) void
port_load_current_map_view_begin_copy_row(
	struct load_current_map_view_state *state)
{
	state->registers.c = SCREEN_WIDTH;
}

/* Returns one while another tile remains in the current 20-tile row. */
__attribute__((noinline, used)) port_u8
port_load_current_map_view_copy_step(
	struct load_current_map_view_state *state)
{
	port_u16 hl = map_view_pair(state->registers.h, state->registers.l);
	port_u16 de = map_view_pair(state->registers.d, state->registers.e);

	state->registers.a = state->fetched_copy;
	state->written_copy = state->registers.a;
	state->write_h = state->registers.d;
	state->write_l = state->registers.e;
	map_view_set_pair(&state->registers.h, &state->registers.l,
	    (port_u16)(hl + 1));
	map_view_set_pair(&state->registers.d, &state->registers.e,
	    (port_u16)(de + 1));
	map_view_dec(&state->registers.c, &state->registers.f);
	return state->registers.c != 0;
}

/* Returns one while another one of the 18 visible rows remains. */
__attribute__((noinline, used)) port_u8
port_load_current_map_view_next_copy_row(
	struct load_current_map_view_state *state)
{
	state->registers.a = SURROUNDING_WIDTH - SCREEN_WIDTH;
	map_view_add_a(&state->registers, state->registers.l);
	state->registers.l = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) != 0)
		state->registers.h++;
	map_view_dec(&state->registers.b, &state->registers.f);
	return state->registers.b != 0;
}

__attribute__((noinline, used)) void
port_load_current_map_view_finish(struct load_current_map_view_state *state)
{
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	state->loaded_rom_bank = state->registers.a;
	state->mapper_bank = state->registers.a;
}

/* Port of LoadCurrentMapView in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_current_map_view(
	struct load_current_map_view_state *state, port_u8 *memory)
{
	struct draw_tile_block_state draw;
	port_u16 address;

	port_load_current_map_view_begin(state);
	do {
		port_load_current_map_view_begin_render_row(state);
		do {
			address = map_view_pair(state->registers.d,
			    state->registers.e);
			state->fetched_block = memory[address];
		} while (port_load_current_map_view_draw_step(state, &draw,
		    memory) != 0);
	} while (port_load_current_map_view_next_render_row(state) != 0);
	port_load_current_map_view_prepare_copy(state);
	do {
		port_load_current_map_view_begin_copy_row(state);
		do {
			address = map_view_pair(state->registers.h,
			    state->registers.l);
			state->fetched_copy = memory[address];
			(void)port_load_current_map_view_copy_step(state);
			address = map_view_pair(state->write_h, state->write_l);
			memory[address] = state->written_copy;
		} while (state->registers.c != 0);
	} while (port_load_current_map_view_next_copy_row(state) != 0);
	port_load_current_map_view_finish(state);
}
