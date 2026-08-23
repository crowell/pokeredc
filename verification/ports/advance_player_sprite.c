#include "port_state.h"

void port_move_tile_block_map_pointer_east(struct register_memory_state *);
void port_move_tile_block_map_pointer_west(struct register_memory_state *);
void port_move_tile_block_map_pointer_south(struct register_memory_state *);
void port_move_tile_block_map_pointer_north(struct register_memory_state *);
void port_load_current_map_view(
	struct load_current_map_view_state *, port_u8 *);
void port_schedule_north_row_redraw(
	struct schedule_north_row_redraw_state *, port_u8 *);
void port_schedule_south_row_redraw(
	struct schedule_south_row_redraw_state *, port_u8 *);
void port_schedule_east_column_redraw(
	struct schedule_east_column_redraw_state *, port_u8 *);
void port_schedule_west_column_redraw(
	struct schedule_west_column_redraw_state *, port_u8 *);

static port_u16
advance_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
advance_add(struct cpu_register_state *registers, port_u8 right)
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
advance_sub(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->a = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
advance_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 value = registers->a;
	advance_sub(registers, right);
	registers->a = value;
}

static void
advance_inc(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 carry = *flags & PORT_FLAG_C;

	(*value)++;
	*flags = carry;
	if (*value == 0)
		*flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		*flags |= PORT_FLAG_H;
}

static void
advance_dec(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 carry = *flags & PORT_FLAG_C;

	(*value)--;
	*flags = (port_u8)(carry | PORT_FLAG_N);
	if (*value == 0)
		*flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		*flags |= PORT_FLAG_H;
}

static void
advance_and(struct cpu_register_state *registers, port_u8 right)
{
	registers->a &= right;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
advance_or(struct cpu_register_state *registers, port_u8 right)
{
	registers->a |= right;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
advance_xor_a(struct cpu_register_state *registers)
{
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
}

static void
advance_sla(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;

	*value <<= 1;
	*flags = 0;
	if (*value == 0)
		*flags |= PORT_FLAG_Z;
	if ((old & 0x80) != 0)
		*flags |= PORT_FLAG_C;
}

/* Returns one for the first animation iteration and zero for the scroll path. */
__attribute__((noinline, used)) port_u8
port_advance_player_sprite_begin(struct advance_player_sprite_state *state)
{
	state->registers.a = state->y_step;
	state->registers.b = state->registers.a;
	state->registers.a = state->x_step;
	state->registers.c = state->registers.a;
	state->registers.h = 0xcf;
	state->registers.l = 0xc5;
	advance_dec(&state->walk_counter, &state->registers.f);
	if (state->walk_counter == 0) {
		state->registers.a = state->y_coord;
		advance_add(&state->registers, state->registers.b);
		state->y_coord = state->registers.a;
		state->registers.a = state->x_coord;
		advance_add(&state->registers, state->registers.c);
		state->x_coord = state->registers.a;
	}
	state->registers.a = state->walk_counter;
	advance_cp(&state->registers, 7);
	return state->registers.a == 7;
}

__attribute__((noinline, used)) void
port_advance_player_sprite_adjust_vram(
	struct advance_player_sprite_state *state)
{
	state->registers.a = state->registers.c;
	advance_cp(&state->registers, 1);
	if (state->registers.a == 1) {
		state->registers.a = state->map_view_vram_low;
		state->registers.e = state->registers.a;
		advance_and(&state->registers, 0xe0);
		state->registers.d = state->registers.a;
		state->registers.a = state->registers.e;
		advance_add(&state->registers, 2);
		advance_and(&state->registers, 0x1f);
		advance_or(&state->registers, state->registers.d);
		state->map_view_vram_low = state->registers.a;
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.a = state->map_view_vram_low;
		state->registers.e = state->registers.a;
		advance_and(&state->registers, 0xe0);
		state->registers.d = state->registers.a;
		state->registers.a = state->registers.e;
		advance_sub(&state->registers, 2);
		advance_and(&state->registers, 0x1f);
		advance_or(&state->registers, state->registers.d);
		state->map_view_vram_low = state->registers.a;
		return;
	}
	state->registers.a = state->registers.b;
	advance_cp(&state->registers, 1);
	if (state->registers.a == 1) {
		state->registers.a = state->map_view_vram_low;
		advance_add(&state->registers, 0x40);
		state->map_view_vram_low = state->registers.a;
		if ((state->registers.f & PORT_FLAG_C) != 0) {
			state->registers.a = state->map_view_vram_high;
			advance_inc(&state->registers.a, &state->registers.f);
			advance_and(&state->registers, 3);
			advance_or(&state->registers, 0x98);
			state->map_view_vram_high = state->registers.a;
		}
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.a = state->map_view_vram_low;
		advance_sub(&state->registers, 0x40);
		state->map_view_vram_low = state->registers.a;
		if ((state->registers.f & PORT_FLAG_C) != 0) {
			state->registers.a = state->map_view_vram_high;
			advance_dec(&state->registers.a, &state->registers.f);
			advance_and(&state->registers, 3);
			advance_or(&state->registers, 0x98);
			state->map_view_vram_high = state->registers.a;
		}
	}
}

static void
advance_pointer_call(struct advance_player_sprite_state *state, port_u8 kind)
{
	struct register_memory_state pointer;

	pointer.registers = state->registers;
	pointer.memory[0] = state->map_view_pointer_low;
	pointer.memory[1] = state->map_view_pointer_high;
	if (kind == 1)
		port_move_tile_block_map_pointer_east(&pointer);
	else if (kind == 2)
		port_move_tile_block_map_pointer_west(&pointer);
	else if (kind == 3)
		port_move_tile_block_map_pointer_south(&pointer);
	else
		port_move_tile_block_map_pointer_north(&pointer);
	state->registers = pointer.registers;
	state->map_view_pointer_low = pointer.memory[0];
	state->map_view_pointer_high = pointer.memory[1];
}

__attribute__((noinline, used)) void
port_advance_player_sprite_adjust_map(
	struct advance_player_sprite_state *state)
{
	state->registers.a = state->registers.c;
	advance_and(&state->registers, state->registers.a);
	state->registers.h = 0xd3;
	state->registers.l = 0x64;
	state->registers.a = state->x_block_coord;
	advance_add(&state->registers, state->registers.c);
	state->x_block_coord = state->registers.a;
	advance_cp(&state->registers, 2);
	if (state->registers.a == 2) {
		advance_xor_a(&state->registers);
		state->x_block_coord = state->registers.a;
		state->registers.h = 0xd4;
		state->registers.l = 0xe3;
		advance_inc(&state->x_special_warp_offset, &state->registers.f);
		state->registers.d = 0xd3;
		state->registers.e = 0x5f;
		advance_pointer_call(state, 1);
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.a = 1;
		state->x_block_coord = state->registers.a;
		state->registers.h = 0xd4;
		state->registers.l = 0xe3;
		advance_dec(&state->x_special_warp_offset, &state->registers.f);
		state->registers.d = 0xd3;
		state->registers.e = 0x5f;
		advance_pointer_call(state, 2);
		return;
	}
	state->registers.h = 0xd3;
	state->registers.l = 0x63;
	state->registers.a = state->y_block_coord;
	advance_add(&state->registers, state->registers.b);
	state->y_block_coord = state->registers.a;
	advance_cp(&state->registers, 2);
	if (state->registers.a == 2) {
		advance_xor_a(&state->registers);
		state->y_block_coord = state->registers.a;
		state->registers.h = 0xd4;
		state->registers.l = 0xe2;
		advance_inc(&state->y_special_warp_offset, &state->registers.f);
		state->registers.d = 0xd3;
		state->registers.e = 0x5f;
		state->registers.a = state->map_width;
		advance_pointer_call(state, 3);
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.a = 1;
		state->y_block_coord = state->registers.a;
		state->registers.h = 0xd4;
		state->registers.l = 0xe2;
		advance_dec(&state->y_special_warp_offset, &state->registers.f);
		state->registers.d = 0xd3;
		state->registers.e = 0x5f;
		state->registers.a = state->map_width;
		advance_pointer_call(state, 4);
	}
}

static void
advance_view_to_local(struct advance_player_sprite_state *state,
	struct load_current_map_view_state *view)
{
	view->registers = state->registers;
	view->tileset_bank = state->tileset_bank;
	view->loaded_rom_bank = state->loaded_rom_bank;
	view->mapper_bank = state->mapper_bank;
	view->map_view_pointer_low = state->map_view_pointer_low;
	view->map_view_pointer_high = state->map_view_pointer_high;
	view->map_width = state->map_width;
	view->y_block_coord = state->y_block_coord;
	view->x_block_coord = state->x_block_coord;
	view->tileset_blocks_low = state->tileset_blocks_low;
	view->tileset_blocks_high = state->tileset_blocks_high;
	view->saved_a = state->view_saved_a;
	view->saved_f = state->view_saved_f;
	view->row_d = state->view_row_d;
	view->row_e = state->view_row_e;
	view->row_h = state->view_row_h;
	view->row_l = state->view_row_l;
	view->fetched_block = state->view_fetched_block;
	view->fetched_copy = state->view_fetched_copy;
	view->written_copy = state->view_written_copy;
	view->write_h = state->view_write_h;
	view->write_l = state->view_write_l;
}

static void
advance_view_from_local(struct advance_player_sprite_state *state,
	const struct load_current_map_view_state *view)
{
	state->registers = view->registers;
	state->tileset_bank = view->tileset_bank;
	state->loaded_rom_bank = view->loaded_rom_bank;
	state->mapper_bank = view->mapper_bank;
	state->map_view_pointer_low = view->map_view_pointer_low;
	state->map_view_pointer_high = view->map_view_pointer_high;
	state->map_width = view->map_width;
	state->y_block_coord = view->y_block_coord;
	state->x_block_coord = view->x_block_coord;
	state->tileset_blocks_low = view->tileset_blocks_low;
	state->tileset_blocks_high = view->tileset_blocks_high;
	state->view_saved_a = view->saved_a;
	state->view_saved_f = view->saved_f;
	state->view_row_d = view->row_d;
	state->view_row_e = view->row_e;
	state->view_row_h = view->row_h;
	state->view_row_l = view->row_l;
	state->view_fetched_block = view->fetched_block;
	state->view_fetched_copy = view->fetched_copy;
	state->view_written_copy = view->written_copy;
	state->view_write_h = view->write_h;
	state->view_write_l = view->write_l;
}

static void
advance_schedule(struct advance_player_sprite_state *state,
	port_u8 *memory, port_u8 kind)
{
#define COPY_SCHEDULE_TO_LOCAL(local) do { \
	(local).registers = state->registers; \
	(local).map_view_vram_low = state->map_view_vram_low; \
	(local).map_view_vram_high = state->map_view_vram_high; \
	(local).redraw_dest_low = state->redraw_dest_low; \
	(local).redraw_dest_high = state->redraw_dest_high; \
	(local).redraw_mode = state->redraw_mode; \
} while (0)
#define COPY_SCHEDULE_FROM_LOCAL(local) do { \
	state->registers = (local).registers; \
	state->map_view_vram_low = (local).map_view_vram_low; \
	state->map_view_vram_high = (local).map_view_vram_high; \
	state->redraw_dest_low = (local).redraw_dest_low; \
	state->redraw_dest_high = (local).redraw_dest_high; \
	state->redraw_mode = (local).redraw_mode; \
} while (0)
	if (kind == 1) {
		struct schedule_south_row_redraw_state local;
		COPY_SCHEDULE_TO_LOCAL(local);
		port_schedule_south_row_redraw(&local, memory);
		COPY_SCHEDULE_FROM_LOCAL(local);
	} else if (kind == 2) {
		struct schedule_north_row_redraw_state local;
		COPY_SCHEDULE_TO_LOCAL(local);
		port_schedule_north_row_redraw(&local, memory);
		COPY_SCHEDULE_FROM_LOCAL(local);
	} else if (kind == 3) {
		struct schedule_east_column_redraw_state local;
		COPY_SCHEDULE_TO_LOCAL(local);
		port_schedule_east_column_redraw(&local, memory);
		COPY_SCHEDULE_FROM_LOCAL(local);
	} else {
		struct schedule_west_column_redraw_state local;
		COPY_SCHEDULE_TO_LOCAL(local);
		port_schedule_west_column_redraw(&local, memory);
		COPY_SCHEDULE_FROM_LOCAL(local);
	}
#undef COPY_SCHEDULE_TO_LOCAL
#undef COPY_SCHEDULE_FROM_LOCAL
}

__attribute__((noinline, used)) void
port_advance_player_sprite_update_view(
	struct advance_player_sprite_state *state, port_u8 *memory)
{
	struct load_current_map_view_state view;

	advance_view_to_local(state, &view);
	port_load_current_map_view(&view, memory);
	advance_view_from_local(state, &view);
	state->registers.a = state->y_step;
	advance_cp(&state->registers, 1);
	if (state->registers.a == 1) {
		advance_schedule(state, memory, 1);
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		advance_schedule(state, memory, 2);
		return;
	}
	state->registers.a = state->x_step;
	advance_cp(&state->registers, 1);
	if (state->registers.a == 1) {
		advance_schedule(state, memory, 3);
		return;
	}
	advance_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		advance_schedule(state, memory, 4);
}

/* Returns one when the sprite-shift loop must execute. */
__attribute__((noinline, used)) port_u8
port_advance_player_sprite_scroll_begin(
	struct advance_player_sprite_state *state)
{
	state->registers.a = state->y_step;
	state->registers.b = state->registers.a;
	state->registers.a = state->x_step;
	state->registers.c = state->registers.a;
	advance_sla(&state->registers.b, &state->registers.f);
	advance_sla(&state->registers.c, &state->registers.f);
	state->registers.a = state->scroll_y;
	advance_add(&state->registers, state->registers.b);
	state->scroll_y = state->registers.a;
	state->registers.a = state->scroll_x;
	advance_add(&state->registers, state->registers.c);
	state->scroll_x = state->registers.a;
	state->registers.h = 0xc1;
	state->registers.l = 0x14;
	state->registers.a = state->num_sprites;
	advance_and(&state->registers, state->registers.a);
	if (state->registers.a == 0)
		return 0;
	state->registers.e = state->registers.a;
	return 1;
}

/* Returns one while another sprite remains to be shifted. */
__attribute__((noinline, used)) port_u8
port_advance_player_sprite_shift_step(
	struct advance_player_sprite_state *state)
{
	port_u16 hl;
	port_u8 old_l;

	state->registers.a = state->sprite_fetched_y;
	advance_sub(&state->registers, state->registers.b);
	state->sprite_written_y = state->registers.a;
	state->sprite_write_y_high = state->registers.h;
	state->sprite_write_y_low = state->registers.l;
	hl = (port_u16)(advance_pair(state->registers.h,
	    state->registers.l) + 1);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.l++;
	state->registers.a = state->sprite_fetched_x;
	advance_sub(&state->registers, state->registers.c);
	state->sprite_written_x = state->registers.a;
	state->sprite_write_x_high = state->registers.h;
	state->sprite_write_x_low = state->registers.l;
	state->registers.a = 14;
	old_l = state->registers.l;
	advance_add(&state->registers, old_l);
	state->registers.l = state->registers.a;
	advance_dec(&state->registers.e, &state->registers.f);
	return state->registers.e != 0;
}

/* Port of AdvancePlayerSprite in home/overworld.asm. */
__attribute__((noinline, used)) void
port_advance_player_sprite(
	struct advance_player_sprite_state *state, port_u8 *memory)
{
	port_u16 address;

	if (port_advance_player_sprite_begin(state) != 0) {
		port_advance_player_sprite_adjust_vram(state);
		port_advance_player_sprite_adjust_map(state);
		port_advance_player_sprite_update_view(state, memory);
	}
	if (port_advance_player_sprite_scroll_begin(state) == 0)
		return;
	do {
		address = advance_pair(state->registers.h, state->registers.l);
		state->sprite_fetched_y = memory[address];
		address++;
		address = (port_u16)((address & 0xff00) |
		    ((address + 1) & 0xff));
		state->sprite_fetched_x = memory[address];
		(void)port_advance_player_sprite_shift_step(state);
		memory[advance_pair(state->sprite_write_y_high,
		    state->sprite_write_y_low)] = state->sprite_written_y;
		memory[advance_pair(state->sprite_write_x_high,
		    state->sprite_write_x_low)] = state->sprite_written_x;
	} while (state->registers.e != 0);
}
