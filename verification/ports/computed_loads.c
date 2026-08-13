#include "port_state.h"

/* Port of ReadNextInputByte in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_read_next_input_byte(struct next_input_byte_state *state)
{
	port_u8 original_low = state->pointer_low;
	port_u8 original_high = state->pointer_high;
	port_u16 address = (port_u16)(((port_u16)original_high << 8) |
		original_low);
	port_u16 next = (port_u16)(address + 1);
	port_u8 fetched;

	state->registers.a = original_low;
	state->registers.l = state->registers.a;
	state->registers.a = original_high;
	state->registers.h = state->registers.a;
	if (address == 0xd0ab)
		fetched = original_low;
	else if (address == 0xd0ac)
		fetched = original_high;
	else
		fetched = state->source;
	state->registers.a = fetched;
	state->registers.h = (port_u8)(next >> 8);
	state->registers.l = (port_u8)next;
	state->registers.b = state->registers.a;
	state->registers.a = state->registers.l;
	state->pointer_low = state->registers.a;
	state->registers.a = state->registers.h;
	state->pointer_high = state->registers.a;
	if (address == 0xd0ab)
		state->source = state->pointer_low;
	else if (address == 0xd0ac)
		state->source = state->pointer_high;
	state->registers.a = state->registers.b;
}

static void
box_add_hl_de(struct cpu_register_state *registers)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	port_u16 de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	port_u16 result = (port_u16)(hl + de);
	port_u8 z = registers->f & PORT_FLAG_Z;

	registers->f = z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Port of GetBoxSRAMLocation in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_get_box_sram_location(struct box_sram_location_state *state)
{
	port_u8 old_a;
	port_u8 old_b;

	state->registers.h = 0x78;
	state->registers.l = 0x95;
	state->registers.a = state->current_box;
	state->registers.a &= 0x7f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	old_a = state->registers.a;
	state->registers.f = PORT_FLAG_N;
	if (old_a == 6)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) < 6)
		state->registers.f |= PORT_FLAG_H;
	if (old_a < 6)
		state->registers.f |= PORT_FLAG_C;
	state->registers.b = 2;
	if (old_a >= 6) {
		old_b = state->registers.b;
		state->registers.b++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.b == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_b & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
		state->registers.a = (port_u8)(old_a - 6);
		state->registers.f = PORT_FLAG_N;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_a & 0x0f) < 6)
			state->registers.f |= PORT_FLAG_H;
		if (old_a < 6)
			state->registers.f |= PORT_FLAG_C;
	}
	state->registers.e = state->registers.a;
	state->registers.d = 0;
	box_add_hl_de(&state->registers);
	box_add_hl_de(&state->registers);
	state->registers.a = state->fetched_low;
	state->registers.h = state->fetched_high;
	state->registers.l = state->registers.a;
}

static void
add_e_and_load(struct computed_load_state *state)
{
	port_u8 left = state->registers.a;
	port_u8 right = state->registers.e;
	port_u16 wide = (port_u16)left + right;
	port_u8 result = (port_u8)wide;
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		flags |= PORT_FLAG_H;
	if (wide > 0xff)
		flags |= PORT_FLAG_C;
	state->registers.a = result;
	state->registers.e = result;
	state->registers.f = flags;
	if ((flags & PORT_FLAG_C) != 0) {
		port_u8 previous_d = state->registers.d;
		state->registers.d++;
		state->registers.f = PORT_FLAG_C;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((previous_d & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.a = state->fetched;
}

/* Port of LoadDEPlusA in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_load_de_plus_a(struct computed_load_state *state)
{
	add_e_and_load(state);
}

/* Port of ReverseNybble in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_reverse_nybble(struct computed_load_state *state)
{
	state->registers.d = 0x28;
	state->registers.e = 0x67;
	add_e_and_load(state);
}

static void
compare_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	registers->f = flags;
}

/* Port of SlotMachine_CheckForMatch in engine/slots/slot_machine.asm. */
__attribute__((noinline, used)) void
port_slot_machine_check_for_match(struct match_check_state *state)
{
	state->registers.a = state->de_value;
	compare_a(&state->registers, state->hl_value);
	if ((state->registers.f & PORT_FLAG_Z) == 0)
		return;
	state->registers.a = state->bc_value;
	compare_a(&state->registers, state->hl_value);
}

/* Port of TMToMove in engine/items/tms.asm. */
__attribute__((noinline, used)) void
port_tm_to_move(struct indexed_load_state *state)
{
	port_u8 offset = (port_u8)(state->value - 1);
	port_u16 hl = 0x7773 + offset;

	state->registers.a = state->fetched;
	state->registers.f = state->value == 1 ? PORT_FLAG_Z : 0;
	state->registers.b = 0;
	state->registers.c = offset;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->value = state->fetched;
}

__attribute__((noinline, used)) void
port_pokedex_to_index_begin(struct indexed_load_state *state)
{
	state->registers.a = state->value;
	state->registers.b = state->registers.a;
	state->registers.c = 0;
	state->registers.h = 0x50;
	state->registers.l = 0x24;
}

__attribute__((noinline, used)) port_u8
port_pokedex_to_index_step(struct indexed_load_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;

	state->registers.c++;
	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	compare_a(&state->registers, state->registers.b);
	return state->registers.a == state->registers.b;
}

__attribute__((noinline, used)) void
port_pokedex_to_index_finish(struct indexed_load_state *state)
{
	state->registers.a = state->registers.c;
	state->value = state->registers.a;
}

/* Port of PokedexToIndex in engine/menus/pokedex.asm. */
__attribute__((noinline, used)) void
port_pokedex_to_index(struct indexed_load_state *state, port_u8 *table)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 offset = 0;

	port_pokedex_to_index_begin(state);
	do {
		state->fetched = table[offset++];
	} while (!port_pokedex_to_index_step(state));
	port_pokedex_to_index_finish(state);
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}

/* Port of IndexToPokedex in engine/menus/pokedex.asm. */
__attribute__((noinline, used)) void
port_index_to_pokedex(struct indexed_load_state *state)
{
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;

	state->registers.a = state->value;
	state->registers.a--;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0x50;
	state->registers.l = 0x24;
	state->registers.b = 0;
	state->registers.c = state->registers.a;
	state->registers.a = state->fetched;
	state->value = state->registers.a;
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}

/* Port of GetMonSpecies in engine/battle/misc.asm. */
__attribute__((noinline, used)) void
port_get_mon_species(struct species_load_state *state)
{
	port_u16 base;
	port_u16 hl;
	port_u8 flags = 0;

	state->registers.a = state->data_location;
	if (state->data_location == 0) {
		base = 0xd164;
	} else if (state->data_location == 1) {
		base = 0xd89d;
	} else {
		base = 0xda81;
	}
	state->registers.d = 0;
	hl = base + state->registers.e;
	if (state->data_location <= 1)
		flags |= PORT_FLAG_Z;
	if ((base & 0x0fff) + state->registers.e > 0x0fff)
		flags |= PORT_FLAG_H;
	if ((unsigned long)base + state->registers.e > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->fetched;
	state->species = state->registers.a;
}

/* Port of ReadTrainerScreenPosition in engine/overworld/trainer_sight.asm. */
__attribute__((noinline, used)) void
port_read_trainer_screen_position(struct trainer_position_state *state)
{
	port_u8 offset;
	port_u16 hl;

	state->registers.a = state->sprite_offset;
	offset = (port_u8)(state->registers.a + 4);
	state->registers.d = 0;
	state->registers.e = offset;
	hl = 0xc100 + offset;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->fetched_y;
	state->screen_y = state->registers.a;
	state->registers.a = state->sprite_offset;
	offset = (port_u8)(state->registers.a + 6);
	state->registers.d = 0;
	state->registers.e = offset;
	hl = 0xc100 + offset;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f = offset == 0 ? PORT_FLAG_Z : 0;
	state->registers.a = state->fetched_x;
	state->screen_x = state->registers.a;
}

/* Port of AdvanceScriptedNPCAnimFrameCounter. */
__attribute__((noinline, used)) void
port_advance_scripted_npc_anim_frame_counter(
	struct sprite_anim_counter_state *state)
{
	port_u8 old;
	port_u8 result;
	port_u8 flags;

	state->registers.a = state->current_sprite_offset;
	state->registers.a += 7;
	state->registers.l = state->registers.a;
	old = state->intra_frame_counter;
	state->registers.a = (port_u8)(old + 1);
	state->intra_frame_counter = state->registers.a;
	result = (port_u8)(state->registers.a - 4);
	flags = PORT_FLAG_N;
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((state->registers.a & 0x0f) < 4)
		flags |= PORT_FLAG_H;
	if (state->registers.a < 4)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	if (state->registers.a != 4)
		return;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->intra_frame_counter = 0;
	state->registers.l++;
	state->registers.a = state->animation_frame_counter;
	state->registers.a++;
	state->registers.a &= 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->animation_frame_counter = state->registers.a;
	state->output_frame_counter = state->registers.a;
}

__attribute__((noinline, used)) void
port_set_last_blackout_map_begin(struct blackout_map_state *state)
{
	state->registers.h = 0x70;
	state->registers.l = 0x92;
	state->registers.a = state->current_map;
	state->registers.b = state->registers.a;
}

/* Returns 0 to continue, 1 for a rest-house match, and 2 at the terminator. */
__attribute__((noinline, used)) port_u8
port_set_last_blackout_map_step(struct blackout_map_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	compare_a(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 2;
	compare_a(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b)
		return 1;
	return 0;
}

__attribute__((noinline, used)) void
port_set_last_blackout_map_not_resthouse(struct blackout_map_state *state)
{
	state->registers.a = state->last_map;
	state->last_blackout_map = state->registers.a;
}

/* Port of SetLastBlackoutMap in engine/events/set_blackout_map.asm. */
__attribute__((noinline, used)) void
port_set_last_blackout_map(struct blackout_map_state *state, port_u8 *table)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 offset = 0;
	port_u8 result;

	port_set_last_blackout_map_begin(state);
	do {
		state->fetched = table[offset++];
		result = port_set_last_blackout_map_step(state);
	} while (result == 0);
	if (result == 2)
		port_set_last_blackout_map_not_resthouse(state);
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}

/* Port of GetTitleBallY in engine/movie/title2.asm. */
__attribute__((noinline, used)) void
port_get_title_ball_y(struct title_ball_y_state *state)
{
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 old_e;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.d = state->registers.a;
	state->registers.h = 0x72;
	state->registers.l = 0xa0;
	state->registers.a = state->fetched;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	state->output_y = state->registers.a;
	old_e = state->registers.e;
	state->registers.e++;
	state->registers.f = 0;
	if (state->registers.e == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_e & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
}

/* Port of ReadSpriteSheetData in engine/overworld/map_sprites.asm. */
__attribute__((noinline, used)) void
port_read_sprite_sheet_data(struct sprite_sheet_data_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched[0];
	hl++;
	state->registers.e = state->registers.a;
	state->registers.a = state->fetched[1];
	hl++;
	state->registers.d = state->registers.a;
	state->registers.a = state->fetched[2];
	hl++;
	state->registers.c = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.b = state->registers.a;
	state->registers.a = state->fetched[3];
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) void
port_is_in_rest_of_array_begin(struct computed_load_state *state)
{
	state->registers.c = state->registers.a;
}

/* Returns 0 to continue, 1 when found, and 2 at the terminator. */
__attribute__((noinline, used)) port_u8
port_is_in_rest_of_array_step(struct computed_load_state *state)
{
	port_u16 hl;
	port_u16 de;
	port_u16 next_hl;
	port_u8 old_b;

	state->registers.a = state->fetched;
	compare_a(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.f = PORT_FLAG_H;
		return 2;
	}
	compare_a(&state->registers, state->registers.c);
	if (state->registers.a == state->registers.c) {
		state->registers.f = PORT_FLAG_Z | PORT_FLAG_C;
		return 1;
	}
	old_b = state->registers.b;
	state->registers.b++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
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

/* Port of IsInRestOfArray in home/array2.asm. */
__attribute__((noinline, used)) port_u8
port_is_in_rest_of_array(struct computed_load_state *state,
	const port_u8 *memory)
{
	port_u8 result;
	port_u16 hl;

	port_is_in_rest_of_array_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[hl];
		result = port_is_in_rest_of_array_step(state);
	} while (result == 0);
	return result;
}

/* Port of GetTextBoxIDCoords in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_get_text_box_id_coords(struct text_box_coords_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 before_dec;
	port_u8 carry;

	state->registers.a = state->fetched[0];
	hl++;
	state->registers.e = state->registers.a;
	state->registers.a = state->fetched[1];
	hl++;
	state->registers.d = state->registers.a;
	state->registers.a = state->fetched[2];
	hl++;
	state->registers.a = (port_u8)(state->registers.a - state->registers.e);
	state->registers.a--;
	state->registers.c = state->registers.a;
	state->registers.a = state->fetched[3];
	hl++;
	carry = state->registers.a < state->registers.d;
	before_dec = (port_u8)(state->registers.a - state->registers.d);
	state->registers.a = (port_u8)(before_dec - 1);
	state->registers.f = PORT_FLAG_N;
	if (carry)
		state->registers.f |= PORT_FLAG_C;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((before_dec & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.b = state->registers.a;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
