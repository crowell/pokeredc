#include "port_state.h"

static void
table_string_add_hl_bc(struct cpu_register_state *registers)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	port_u16 bc = (port_u16)(((port_u16)registers->b << 8) | registers->c);
	port_u16 result = (port_u16)(hl + bc);
	port_u8 z = registers->f & PORT_FLAG_Z;

	registers->f = z;
	if ((hl & 0x0fff) + (bc & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if ((unsigned long)hl + bc > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

static void
table_string_setup(struct table_string_copy_state *state,
	port_u16 table, port_u8 decrement)
{
	port_u8 old_a;

	state->registers.h = (port_u8)(table >> 8);
	state->registers.l = (port_u8)table;
	state->registers.a = state->selector;
	if (decrement) {
		old_a = state->registers.a;
		state->registers.a--;
		state->registers.f &= PORT_FLAG_C;
		state->registers.f |= PORT_FLAG_N;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_a & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	table_string_add_hl_bc(&state->registers);
	table_string_add_hl_bc(&state->registers);
	state->registers.a = state->pointer_low;
	state->registers.h = state->pointer_high;
	state->registers.l = state->registers.a;
	state->registers.d = 0xcd;
	state->registers.e = 0x6d;
}

__attribute__((noinline, used)) void
port_route23_copy_badge_text_begin(struct table_string_copy_state *state)
{
	table_string_setup(state, 0x5276, 0);
}

__attribute__((noinline, used)) void
port_save_trainer_name_begin(struct table_string_copy_state *state)
{
	table_string_setup(state, 0x7e64, 1);
}

__attribute__((noinline, used)) port_u8
port_table_string_copy_step(struct table_string_copy_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 left;
	port_u8 right = 0x50;

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	left = state->registers.a;
	state->registers.f = PORT_FLAG_N;
	if (left == right)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (left < right)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return left == right;
}

static void
table_string_copy(struct table_string_copy_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	do {
		source = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		destination = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched = memory[source];
		port_table_string_copy_step(state);
		memory[destination] = state->written;
	} while (state->registers.a != 0x50);
}

__attribute__((noinline, used)) void
port_route23_copy_badge_text(struct table_string_copy_state *state,
	port_u8 *memory)
{
	port_route23_copy_badge_text_begin(state);
	table_string_copy(state, memory);
}

__attribute__((noinline, used)) void
port_save_trainer_name(struct table_string_copy_state *state, port_u8 *memory)
{
	port_save_trainer_name_begin(state);
	table_string_copy(state, memory);
}

__attribute__((noinline, used)) port_u8
port_copy_string_step(
	struct copy_string_step_state *state, port_u8 fetched)
{
	port_u16 de = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 result;
	port_u8 flags = PORT_FLAG_N;

	state->registers.a = fetched;
	de++;
	hl++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->written = fetched;
	result = (port_u8)(fetched - 0x50);
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if (fetched < 0x50)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	return fetched == 0x50;
}

/* Port of CopyString in home/copy_string.asm. */
__attribute__((noinline, used)) void
port_copy_string(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 de;
	port_u16 hl;

	step.registers = *state;
	do {
		de = ((port_u16)step.registers.d << 8) | step.registers.e;
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		if (port_copy_string_step(&step, memory[de])) {
			memory[hl] = step.written;
			break;
		}
		memory[hl] = step.written;
	} while (1);
	*state = step.registers;
}

__attribute__((noinline, used)) port_u8
port_reset_stats_step(
	struct copy_string_step_state *state, port_u8 fetched)
{
	port_u16 de = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 previous_b;
	port_u8 flags;

	state->registers.a = fetched;
	hl++;
	de++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->written = fetched;
	previous_b = state->registers.b;
	state->registers.b--;
	flags = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.b == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_b & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.b == 0;
}

__attribute__((noinline, used)) void
port_reset_stats_begin(struct cpu_register_state *state)
{
	state->b = 8;
}

/* Port of ResetStats in engine/battle/move_effects/haze.asm. */
__attribute__((noinline, used)) void
port_reset_stats(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 de;
	port_u16 hl;

	step.registers = *state;
	port_reset_stats_begin(&step.registers);
	do {
		de = ((port_u16)step.registers.d << 8) | step.registers.e;
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		if (port_reset_stats_step(&step, memory[hl])) {
			memory[de] = step.written;
			break;
		}
		memory[de] = step.written;
	} while (1);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_intro_place_black_tiles_begin(struct cpu_register_state *state)
{
	state->a = 1;
}

__attribute__((noinline, used)) port_u8
port_intro_place_black_tiles_step(struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 previous_c = state->registers.c;
	port_u8 flags;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	flags = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.c == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.c == 0;
}

/* Port of IntroPlaceBlackTiles in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_intro_place_black_tiles(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_intro_place_black_tiles_begin(state);
	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_intro_place_black_tiles_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_cable_club_draw_horizontal_line_begin(struct cpu_register_state *state)
{
	state->d = state->c;
}

__attribute__((noinline, used)) port_u8
port_cable_club_draw_horizontal_line_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 previous_d = state->registers.d;
	port_u8 flags;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d--;
	flags = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.d == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_d & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.d == 0;
}

/* Port of CableClub_DrawHorizontalLine in engine/link/cable_club.asm. */
__attribute__((noinline, used)) void
port_cable_club_draw_horizontal_line(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_cable_club_draw_horizontal_line_begin(state);
	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_cable_club_draw_horizontal_line_step(&step);
		memory[hl] = step.written;
	} while (step.registers.d != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_trainer_info_draw_vertical_line_begin(struct cpu_register_state *state)
{
	state->d = 0;
	state->e = 20;
	state->c = 8;
}

__attribute__((noinline, used)) port_u8
port_trainer_info_draw_vertical_line_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u16 de = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u8 previous_c = state->registers.c;
	port_u8 flags = PORT_FLAG_N;
	port_u16 next_hl = hl + de;

	state->written = state->registers.a;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	state->registers.c--;
	if (next_hl < hl)
		flags |= PORT_FLAG_C;
	if (state->registers.c == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.c == 0;
}

/* Port of TrainerInfo_DrawVerticalLine in engine/menus/start_sub_menus.asm. */
__attribute__((noinline, used)) void
port_trainer_info_draw_vertical_line(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_trainer_info_draw_vertical_line_begin(state);
	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_trainer_info_draw_vertical_line_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_draw_pokedex_vertical_line_begin(struct cpu_register_state *state)
{
	state->c = 9;
	state->d = 0;
	state->e = 20;
	state->a = 0x71;
}

__attribute__((noinline, used)) port_u8
port_draw_pokedex_vertical_line_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u16 de = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u8 previous_c = state->registers.c;
	port_u8 flags = PORT_FLAG_N;
	port_u16 next_hl = hl + de;

	state->written = state->registers.a;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	state->registers.a ^= 1;
	state->registers.c--;
	if (state->registers.c == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.c == 0;
}

/* Port of DrawPokedexVerticalLine in engine/menus/pokedex.asm. */
__attribute__((noinline, used)) void
port_draw_pokedex_vertical_line(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_draw_pokedex_vertical_line_begin(state);
	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_draw_pokedex_vertical_line_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_copy_healing_machine_oam_step(
	struct copy_string_step_state *state, port_u8 fetched)
{
	port_u16 de = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;

	state->registers.a = fetched;
	de++;
	hl++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->written = fetched;
}

/* Port of CopyHealingMachineOAM in engine/overworld/healing_machine.asm. */
__attribute__((noinline, used)) void
port_copy_healing_machine_oam(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 de;
	port_u16 hl;
	port_u8 count;

	step.registers = *state;
	for (count = 0; count < 4; count++) {
		de = ((port_u16)step.registers.d << 8) | step.registers.e;
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_copy_healing_machine_oam_step(&step, memory[de]);
		memory[hl] = step.written;
	}
	*state = step.registers;
}

__attribute__((noinline, used)) port_u8
port_shift_font_color_index_step(struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u16 bc = ((port_u16)state->registers.b << 8) | state->registers.c;

	state->written = 0;
	hl += 2;
	bc--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = (port_u8)(bc >> 8);
	state->registers.c = (port_u8)bc;
	state->registers.a = state->registers.b | state->registers.c;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return bc == 0;
}

/* Port of ShiftFontColorIndex in engine/movie/credits.asm. */
__attribute__((noinline, used)) void
port_shift_font_color_index(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_shift_font_color_index_step(&step);
		memory[hl] = 0;
	} while (step.registers.b != 0 || step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_calc_string_length_begin(struct cpu_register_state *state)
{
	state->h = 0xcf;
	state->l = 0x4b;
	state->c = 0;
}

__attribute__((noinline, used)) port_u8
port_calc_string_length_step(struct cpu_register_state *state, port_u8 fetched)
{
	port_u8 flags = PORT_FLAG_N;
	port_u16 hl;
	port_u8 previous_c;

	state->a = fetched;
	if (fetched == 0x50) {
		state->f = PORT_FLAG_Z | PORT_FLAG_N;
		return 1;
	}
	if (fetched < 0x50)
		flags |= PORT_FLAG_C;
	hl = ((port_u16)state->h << 8) | state->l;
	hl++;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
	previous_c = state->c;
	state->c++;
	flags &= PORT_FLAG_C;
	if (state->c == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0x0f)
		flags |= PORT_FLAG_H;
	state->f = flags;
	return 0;
}

/* Port of CalcStringLength in engine/menus/naming_screen.asm. */
__attribute__((noinline, used)) void
port_calc_string_length(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl;

	port_calc_string_length_begin(state);
	do {
		hl = ((port_u16)state->h << 8) | state->l;
	} while (!port_calc_string_length_step(state, memory[hl]));
}

static port_u8
center_cp_flags(port_u8 value)
{
	port_u8 flags = PORT_FLAG_N;

	if (value == 0x50)
		flags |= PORT_FLAG_Z;
	if (value < 0x50)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of CenterMonName in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_center_mon_name(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 original_de = ((port_u16)state->d << 8) | state->e;
	port_u16 de = original_de;
	port_u16 hl = ((port_u16)state->h << 8) | state->l;
	port_u8 count = 2;

	hl += 2;
	state->b = 2;
	do {
		de++;
		state->a = memory[de];
		state->f = center_cp_flags(state->a);
		if (state->a == 0x50)
			break;
		de++;
		state->a = memory[de];
		state->f = center_cp_flags(state->a);
		if (state->a == 0x50)
			break;
		hl--;
		state->b--;
		state->f = (state->f & PORT_FLAG_C) | PORT_FLAG_N;
		if (state->b == 0)
			state->f |= PORT_FLAG_Z;
		if (--count == 0)
			break;
	} while (1);
	state->d = (port_u8)(original_de >> 8);
	state->e = (port_u8)original_de;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}

__attribute__((noinline, used)) port_u8
port_draw_tile_line_step(struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;
	port_u16 de = ((port_u16)state->registers.d << 8) |
		state->registers.e;
	port_u8 previous_c = state->registers.c;
	port_u8 carry;

	state->written = state->registers.b;
	carry = (unsigned long)hl + de > 0xffff ? PORT_FLAG_C : 0;
	hl += de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	state->registers.f = carry | PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of DrawTileLine in engine/menus/pokedex.asm. */
__attribute__((noinline, used)) void
port_draw_tile_line(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u8 saved_b = state->b;
	port_u8 saved_c = state->c;
	port_u8 saved_d = state->d;
	port_u8 saved_e = state->e;
	port_u16 hl;

	step.registers = *state;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_draw_tile_line_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
	state->b = saved_b;
	state->c = saved_c;
	state->d = saved_d;
	state->e = saved_e;
}

__attribute__((noinline, used)) void
port_trainer_info_draw_horizontal_edge_begin(
	struct copy_string_step_state *state, port_u8 width)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = width;
	state->registers.c = state->registers.a;
	state->registers.a = state->registers.d;
}

__attribute__((noinline, used)) port_u8
port_trainer_info_draw_horizontal_edge_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;
	port_u8 previous_c = state->registers.c;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) void
port_trainer_info_draw_horizontal_edge_finish(
	struct copy_string_step_state *state)
{
	state->registers.a = state->registers.e;
	state->written = state->registers.a;
}

/* Port of TrainerInfo_DrawHorizontalEdge. */
__attribute__((noinline, used)) void
port_trainer_info_draw_horizontal_edge(
	struct cpu_register_state *state, port_u8 *memory, port_u8 width)
{
	struct copy_string_step_state step;
	port_u16 hl;

	step.registers = *state;
	hl = ((port_u16)step.registers.h << 8) | step.registers.l;
	port_trainer_info_draw_horizontal_edge_begin(&step, width);
	memory[hl] = step.written;
	do {
		hl = ((port_u16)step.registers.h << 8) | step.registers.l;
		port_trainer_info_draw_horizontal_edge_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	hl = ((port_u16)step.registers.h << 8) | step.registers.l;
	port_trainer_info_draw_horizontal_edge_finish(&step);
	memory[hl] = step.written;
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_battle_transition_vertical_stripes_begin(struct cpu_register_state *state)
{
	state->c = 10;
}

__attribute__((noinline, used)) port_u8
port_battle_transition_vertical_stripes_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c = state->registers.c;

	state->written = 0xff;
	hl = (port_u16)(hl + 2);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.c--;
	state->registers.f = (port_u8)(state->registers.f & PORT_FLAG_C);
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of BattleTransition_VerticalStripes_. */
__attribute__((noinline, used)) void
port_battle_transition_vertical_stripes(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_battle_transition_vertical_stripes_begin(state);
	step.registers = *state;
	do {
		hl = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		port_battle_transition_vertical_stripes_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_battle_transition_horizontal_stripes_begin(struct cpu_register_state *state)
{
	state->c = 9;
	state->d = 0;
	state->e = 40;
}

__attribute__((noinline, used)) port_u8
port_battle_transition_horizontal_stripes_step(
	struct copy_string_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 next_hl = (port_u16)(hl + de);
	port_u8 old_c = state->registers.c;

	state->written = 0xff;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	state->registers.c--;
	state->registers.f = PORT_FLAG_N;
	if (next_hl < hl)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of BattleTransition_HorizontalStripes_. */
__attribute__((noinline, used)) void
port_battle_transition_horizontal_stripes(
	struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_battle_transition_horizontal_stripes_begin(state);
	step.registers = *state;
	do {
		hl = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		port_battle_transition_horizontal_stripes_step(&step);
		memory[hl] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

static void
text_box_search_compare(struct cpu_register_state *state, port_u8 right)
{
	port_u8 left = state->a;

	state->f = PORT_FLAG_N;
	if (left == right)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->f |= PORT_FLAG_H;
	if (left < right)
		state->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_search_text_box_table_begin(struct text_box_search_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);

	de--;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
}

/* Returns 0 to continue, 1 for a match, and 2 for the terminator. */
__attribute__((noinline, used)) port_u8
port_search_text_box_table_step(struct text_box_search_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 next_hl;

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	text_box_search_compare(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 2;
	text_box_search_compare(&state->registers, state->registers.c);
	if (state->registers.a == state->registers.c) {
		state->registers.f =
			(state->registers.f & PORT_FLAG_Z) | PORT_FLAG_C;
		return 1;
	}
	next_hl = (port_u16)(hl + de);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	return 0;
}

/* Port of SearchTextBoxTable in engine/menus/text_box.asm. */
__attribute__((noinline, used)) port_u8
port_search_text_box_table(struct text_box_search_state *state,
	const port_u8 *memory)
{
	port_u16 hl;
	port_u8 result;

	port_search_text_box_table_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[hl];
		result = port_search_text_box_table_step(state);
	} while (result == 0);
	return result;
}

__attribute__((noinline, used)) void
port_erase_party_menu_cursors_begin(struct cpu_register_state *state)
{
	state->h = 0xc3;
	state->l = 0xb4;
	state->b = 0;
	state->c = 40;
	state->a = 6;
}

__attribute__((noinline, used)) port_u8
port_erase_party_menu_cursors_step(struct copy_string_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);
	port_u16 next_hl = (port_u16)(hl + bc);
	port_u8 old_a = state->registers.a;

	state->written = 0x7f;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N;
	if (next_hl < hl)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.a == 0;
}

/* Port of ErasePartyMenuCursors in engine/menus/start_sub_menus.asm. */
__attribute__((noinline, used)) void
port_erase_party_menu_cursors(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	port_erase_party_menu_cursors_begin(state);
	step.registers = *state;
	do {
		hl = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		port_erase_party_menu_cursors_step(&step);
		memory[hl] = step.written;
	} while (step.registers.a != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) port_u8
port_status_screen_print_pp_step(struct status_pp_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 next_hl = (port_u16)(hl + de);
	port_u8 old_c = state->registers.c;

	state->written[0] = state->registers.a;
	state->written[1] = state->registers.a;
	state->registers.h = (port_u8)(next_hl >> 8);
	state->registers.l = (port_u8)next_hl;
	state->registers.c--;
	state->registers.f = PORT_FLAG_N;
	if (next_hl < hl)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of StatusScreen_PrintPP in engine/pokemon/status_screen.asm. */
__attribute__((noinline, used)) void
port_status_screen_print_pp(struct cpu_register_state *state, port_u8 *memory)
{
	struct status_pp_state step;
	port_u16 hl;

	step.registers = *state;
	do {
		hl = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		port_status_screen_print_pp_step(&step);
		memory[hl] = step.written[0];
		memory[(port_u16)(hl + 1)] = step.written[1];
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_copy_map_connection_header_begin(struct copy_byte_step_state *state)
{
	state->registers.c = 11;
}

__attribute__((noinline, used)) port_u8
port_copy_map_connection_header_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_c = state->registers.c;

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of CopyMapConnectionHeader in home/overworld.asm. */
__attribute__((noinline, used)) void
port_copy_map_connection_header(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_byte_step_state step;
	port_u16 source;
	port_u16 destination;

	step.registers = *state;
	port_copy_map_connection_header_begin(&step);
	do {
		source = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		destination = (port_u16)(((port_u16)step.registers.d << 8) |
			step.registers.e);
		step.fetched = memory[source];
		port_copy_map_connection_header_step(&step);
		memory[destination] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_fill_memory_begin(struct fill_memory_state *state)
{
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->registers.d = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_fill_memory_step(struct fill_memory_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;

	state->registers.a = state->registers.d;
	state->written = state->registers.a;
	hl++;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.b = (port_u8)(state->registers.b - (old_c == 0));
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = (port_u8)(state->registers.b | state->registers.c);
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return state->registers.a == 0;
}

__attribute__((noinline, used)) void
port_fill_memory_finish(struct fill_memory_state *state)
{
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
}

/* Port of FillMemory in home/tilemap.asm. */
__attribute__((noinline, used)) void
port_fill_memory(struct fill_memory_state *state, port_u8 *memory)
{
	port_u16 hl;

	port_fill_memory_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		port_fill_memory_step(state);
		memory[hl] = state->written;
	} while (state->registers.b != 0 || state->registers.c != 0);
	port_fill_memory_finish(state);
}

static void
copy_until_compare(struct cpu_register_state *state, port_u8 right)
{
	port_u8 left = state->a;

	state->f = PORT_FLAG_N;
	if (left == right)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->f |= PORT_FLAG_H;
	if (left < right)
		state->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_copy_data_until_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = state->registers.h;
	copy_until_compare(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b)
		return 0;
	state->registers.a = state->registers.l;
	copy_until_compare(&state->registers, state->registers.c);
	return state->registers.a == state->registers.c;
}

/* Port of CopyDataUntil in home/move_mon.asm. */
__attribute__((noinline, used)) void
port_copy_data_until(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_byte_step_state step;
	port_u16 source;
	port_u16 destination;

	step.registers = *state;
	do {
		source = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		destination = (port_u16)(((port_u16)step.registers.d << 8) |
			step.registers.e);
		step.fetched = memory[source];
		port_copy_data_until_step(&step);
		memory[destination] = step.written;
	} while (step.registers.h != step.registers.b ||
		step.registers.l != step.registers.c);
	*state = step.registers;
}

__attribute__((noinline, used)) port_u8
port_copy_data_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	bc--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.b = (port_u8)(bc >> 8);
	state->registers.c = (port_u8)bc;
	state->registers.a = state->registers.c;
	state->registers.a |= state->registers.b;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return state->registers.a == 0;
}

/* Port of CopyData in home/copy.asm. */
__attribute__((noinline, used)) void
port_copy_data(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_byte_step_state step;
	port_u16 source;
	port_u16 destination;

	step.registers = *state;
	do {
		source = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		destination = (port_u16)(((port_u16)step.registers.d << 8) |
			step.registers.e);
		step.fetched = memory[source];
		port_copy_data_step(&step);
		memory[destination] = step.written;
	} while (step.registers.b != 0 || step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_write_mon_moves_shift_move_data_begin(struct copy_byte_step_state *state)
{
	state->registers.c = 3;
}

__attribute__((noinline, used)) port_u8
port_write_mon_moves_shift_move_data_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_c = state->registers.c;

	de++;
	state->registers.a = state->fetched;
	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of WriteMonMoves_ShiftMoveData in engine/pokemon/evos_moves.asm. */
__attribute__((noinline, used)) void
port_write_mon_moves_shift_move_data(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct copy_byte_step_state step;
	port_u16 source;
	port_u16 destination;

	step.registers = *state;
	port_write_mon_moves_shift_move_data_begin(&step);
	do {
		source = (port_u16)((((port_u16)step.registers.d << 8) |
			step.registers.e) + 1);
		destination = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		step.fetched = memory[source];
		port_write_mon_moves_shift_move_data_step(&step);
		memory[destination] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_zero_sprite_buffer_begin(struct cpu_register_state *state)
{
	state->b = 0x01;
	state->c = 0x88;
}

__attribute__((noinline, used)) port_u8
port_zero_sprite_buffer_step(struct copy_string_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;

	state->registers.a = 0;
	state->written = state->registers.a;
	hl++;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.b = (port_u8)(state->registers.b - (old_c == 0));
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = (port_u8)(state->registers.b | state->registers.c);
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	return state->registers.a == 0;
}

/* Port of ZeroSpriteBuffer in home/pics.asm. */
__attribute__((noinline, used)) void
port_zero_sprite_buffer(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_string_step_state step;
	port_u16 hl;

	step.registers = *state;
	port_zero_sprite_buffer_begin(&step.registers);
	do {
		hl = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		port_zero_sprite_buffer_step(&step);
		memory[hl] = step.written;
	} while (step.registers.b != 0 || step.registers.c != 0);
	*state = step.registers;
}

__attribute__((noinline, used)) void
port_copy_to_redraw_src_tiles_begin(struct copy_byte_step_state *state)
{
	state->registers.d = 0xcb;
	state->registers.e = 0xfc;
	state->registers.c = 40;
}

__attribute__((noinline, used)) port_u8
port_copy_to_redraw_src_tiles_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_c = state->registers.c;

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of CopyToRedrawRowOrColumnSrcTiles in home/overworld.asm. */
__attribute__((noinline, used)) void
port_copy_to_redraw_src_tiles(struct cpu_register_state *state, port_u8 *memory)
{
	struct copy_byte_step_state step;
	port_u16 source;
	port_u16 destination;

	step.registers = *state;
	port_copy_to_redraw_src_tiles_begin(&step);
	do {
		source = (port_u16)(((port_u16)step.registers.h << 8) |
			step.registers.l);
		destination = (port_u16)(((port_u16)step.registers.d << 8) |
			step.registers.e);
		step.fetched = memory[source];
		port_copy_to_redraw_src_tiles_step(&step);
		memory[destination] = step.written;
	} while (step.registers.c != 0);
	*state = step.registers;
}
