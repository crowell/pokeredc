#include "port_state.h"

port_u8 port_check_coords(struct check_coords_state *state,
	const port_u8 *memory);

static void
slot_machine_get_wheel_setup(struct slot_machine_wheel_setup_state *state,
	port_u16 destination, port_u16 source)
{
	state->registers.d = (port_u8)(destination >> 8);
	state->registers.e = (port_u8)destination;
	state->registers.h = (port_u8)(source >> 8);
	state->registers.l = (port_u8)source;
	state->registers.a = state->offset;
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel1_tiles_begin(
	struct slot_machine_wheel_setup_state *state)
{
	slot_machine_get_wheel_setup(state, 0xcd41, 0x79e5);
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel2_tiles_begin(
	struct slot_machine_wheel_setup_state *state)
{
	slot_machine_get_wheel_setup(state, 0xcd44, 0x7a09);
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel3_tiles_begin(
	struct slot_machine_wheel_setup_state *state)
{
	slot_machine_get_wheel_setup(state, 0xcd47, 0x7a2d);
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel_tiles_begin(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 offset;
	port_u16 result;

	state->registers.c = state->registers.a;
	state->registers.b = 0;
	offset = state->registers.c;
	result = (port_u16)(hl + offset);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + offset > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + offset > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	state->registers.c = 3;
}

__attribute__((noinline, used)) port_u8
port_slot_machine_get_wheel_tiles_step(struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u8 old_c;

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of SlotMachine_GetWheelTiles in engine/slots/slot_machine.asm. */
__attribute__((noinline, used)) void
port_slot_machine_get_wheel_tiles(
	struct copy_byte_step_state *state, port_u8 *memory)
{
	port_u16 source;
	port_u16 destination;

	port_slot_machine_get_wheel_tiles_begin(state);
	do {
		source = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		destination = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		state->fetched = memory[source];
		port_slot_machine_get_wheel_tiles_step(state);
		memory[destination] = state->written;
	} while (state->registers.c != 0);
}

/*
 * Ports of the three cascading wheel-update entries. The offset occupies the
 * shared copy state's fetched-byte slot and is consumed before that slot is
 * reused by the copy recurrence.
 */
__attribute__((noinline, used)) void
port_slot_machine_get_wheel1_tiles(
	struct slot_machine_wheel_setup_state *state, port_u8 *memory)
{
	port_slot_machine_get_wheel1_tiles_begin(state);
	port_slot_machine_get_wheel_tiles(
		(struct copy_byte_step_state *)state, memory);
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel2_tiles(
	struct slot_machine_wheel_setup_state *state, port_u8 *memory)
{
	port_slot_machine_get_wheel2_tiles_begin(state);
	port_slot_machine_get_wheel_tiles(
		(struct copy_byte_step_state *)state, memory);
	state->offset = memory[0xcd3e];
	port_slot_machine_get_wheel1_tiles(state, memory);
}

__attribute__((noinline, used)) void
port_slot_machine_get_wheel3_tiles(
	struct slot_machine_wheel_setup_state *state, port_u8 *memory)
{
	port_slot_machine_get_wheel3_tiles_begin(state);
	port_slot_machine_get_wheel_tiles(
		(struct copy_byte_step_state *)state, memory);
	state->offset = memory[0xcd3f];
	port_slot_machine_get_wheel2_tiles(state, memory);
}

__attribute__((noinline, used)) void
port_get_mon_counts_for_boxes_in_bank_step(
	struct copy_byte_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched;
	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Port of GetMonCountsForBoxesInBank in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_get_mon_counts_for_boxes_in_bank(
	struct copy_byte_step_state *state, port_u8 *memory)
{
	static const port_u16 sources[6] = {
		0xa000, 0xa462, 0xa8c4, 0xad26, 0xb188, 0xb5ea,
	};
	port_u16 destination;
	port_u8 index;

	for (index = 0; index != 6; index++) {
		destination = (port_u16)(
			((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[sources[index]];
		port_get_mon_counts_for_boxes_in_bank_step(state);
		memory[destination] = state->written;
	}
}

/* Port of BankswitchBack in home/bankswitch.asm. */
__attribute__((noinline, used)) void
port_bankswitch_back(struct memory_transfer_state *state)
{
	state->registers.a = state->memory[0];
	state->memory[1] = state->registers.a;
	state->memory[2] = state->registers.a;
}

/* Port of CinnabarGymSetTrainerHeader in scripts/CinnabarGym.asm. */
__attribute__((noinline, used)) void
port_cinnabar_gym_set_trainer_header(struct memory_transfer_state *state)
{
	state->registers.a = state->memory[0];
	state->memory[1] = state->registers.a;
}

/* Ports of the two identical Silph Co. current-script setters. */
__attribute__((noinline, used)) void
port_silph_co_11f_set_cur_script(struct memory_transfer_state *state)
{
	state->memory[0] = state->registers.a;
	state->memory[1] = state->registers.a;
}

__attribute__((noinline, used)) void
port_silph_co_7f_set_cur_script(struct memory_transfer_state *state)
{
	state->memory[0] = state->registers.a;
	state->memory[1] = state->registers.a;
}

/* Port of StoreTrainerHeaderPointer in home/trainers.asm. */
__attribute__((noinline, used)) void
port_store_trainer_header_pointer(struct memory_transfer_state *state)
{
	state->registers.a = state->registers.h;
	state->memory[0] = state->registers.a;
	state->registers.a = state->registers.l;
	state->memory[1] = state->registers.a;
}

/* Port of StoreSpriteOutputPointer in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_store_sprite_output_pointer(struct button_reset_state *state)
{
	state->registers.a = state->registers.l;
	state->memory[0] = state->registers.a;
	state->memory[1] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[2] = state->registers.a;
	state->memory[3] = state->registers.a;
}

/* Port of RestoreMapTextPointer in home/predef_text.asm. */
__attribute__((noinline, used)) void
port_restore_map_text_pointer(struct button_reset_state *state)
{
	state->registers.h = 0xd3;
	state->registers.l = 0x6c;
	state->registers.a = state->memory[0];
	state->memory[2] = state->registers.a;
	state->registers.l++;
	state->registers.a = state->memory[1];
	state->memory[3] = state->registers.a;
}

static void
trade_anim_entry(
	struct button_reset_state *state, port_u8 left_index, port_u16 sequence)
{
	state->registers.a = state->memory[left_index];
	state->memory[2] = state->registers.a;
	state->registers.a = state->memory[left_index ^ 1];
	state->memory[3] = state->registers.a;
	state->registers.d = (port_u8)(sequence >> 8);
	state->registers.e = (port_u8)sequence;
}

__attribute__((noinline, used)) void
port_internal_clock_trade_anim(struct button_reset_state *state)
{
	trade_anim_entry(state, 0, 0x5138);
}

__attribute__((noinline, used)) void
port_external_clock_trade_anim(struct button_reset_state *state)
{
	trade_anim_entry(state, 1, 0x5149);
}

/* Port of BankswitchHome in home/bankswitch.asm. */
__attribute__((noinline, used)) void
port_bankswitch_home(struct button_reset_state *state)
{
	state->memory[0] = state->registers.a;
	state->registers.a = state->memory[1];
	state->memory[2] = state->registers.a;
	state->registers.a = state->memory[0];
	state->memory[1] = state->registers.a;
	state->memory[3] = state->registers.a;
}

/* Port of PlayBattleAnimation through PlayBattleAnimationGotID. */
__attribute__((noinline, used)) void
port_play_battle_animation(struct memory_predicate_state *state)
{
	state->value = state->registers.a;
}

/* Port of HandleMenuInput through HandleMenuInput_. */
__attribute__((noinline, used)) void
port_handle_menu_input(struct memory_predicate_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->value = 0;
}

/* Port of LoadFlippedFrontSpriteByMonIndex through the normal loader. */
__attribute__((noinline, used)) void
port_load_flipped_front_sprite_by_mon_index(
	struct memory_predicate_state *state)
{
	state->registers.a = 1;
	state->value = 1;
}

/* Port of ArePlayerCoordsInArray through the shared CheckCoords tail. */
__attribute__((noinline, used)) port_u8
port_are_player_coords_in_array(struct are_player_coords_state *state,
	const port_u8 *memory)
{
	state->check.registers.a = state->player_y;
	state->check.registers.b = state->check.registers.a;
	state->check.registers.a = state->player_x;
	state->check.registers.c = state->check.registers.a;
	return port_check_coords(&state->check, memory);
}

static port_u8
inc_flags(port_u8 old, port_u8 result, port_u8 carry)
{
	port_u8 flags = carry & PORT_FLAG_C;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		flags |= PORT_FLAG_H;
	return flags;
}

static port_u8
dec_flags(port_u8 old, port_u8 result, port_u8 carry)
{
	port_u8 flags = (carry & PORT_FLAG_C) | PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	return flags;
}

/* Port of GetCoordsInFrontOfPlayer in engine/events/card_key.asm. */
__attribute__((noinline, used)) void
port_get_coords_in_front_of_player(struct memory_transfer_state *state)
{
	port_u8 old;

	state->registers.a = state->memory[0];
	state->registers.d = state->registers.a;
	state->registers.a = state->memory[1];
	state->registers.e = state->registers.a;
	state->registers.a = state->memory[2];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		old = state->registers.d;
		state->registers.d++;
		state->registers.f = inc_flags(
			old, state->registers.d, state->registers.f);
		return;
	}
	if (state->registers.a == 4) {
		old = state->registers.d;
		state->registers.d--;
		state->registers.f = dec_flags(
			old, state->registers.d, state->registers.f);
		return;
	}
	if (state->registers.a == 8) {
		old = state->registers.e;
		state->registers.e--;
		state->registers.f = dec_flags(
			old, state->registers.e, state->registers.f);
		return;
	}
	old = state->registers.e;
	state->registers.e++;
	state->registers.f = inc_flags(
		old, state->registers.e,
		state->registers.a < 8 ? PORT_FLAG_C : 0);
}

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static port_u8
compare_coord_with_dimension(struct button_reset_state *state)
{
	port_u8 old_b;

	state->registers.a += state->registers.a;
	state->registers.f = cp_flags(
		state->registers.a, state->registers.b);
	if (state->registers.a == state->registers.b)
		return 1;
	old_b = state->registers.b;
	state->registers.b++;
	state->registers.f = inc_flags(
		old_b, state->registers.b, state->registers.f);
	return state->registers.b == 0;
}

/* Port of IsPlayerJustOutsideMap in its entirety. */
__attribute__((noinline, used)) void
port_is_player_just_outside_map(struct button_reset_state *state)
{
	state->registers.a = state->memory[0];
	state->registers.b = state->registers.a;
	state->registers.a = state->memory[1];
	if (compare_coord_with_dimension(state))
		return;
	state->registers.a = state->memory[2];
	state->registers.b = state->registers.a;
	state->registers.a = state->memory[3];
	(void)compare_coord_with_dimension(state);
}

/* Port of GetPartyMonName2 through the shared GetPartyMonName tail. */
__attribute__((noinline, used)) void
port_get_party_mon_name2(struct register_memory_state *state)
{
	state->registers.a = state->memory[0];
	state->registers.h = 0xd2;
	state->registers.l = 0xb5;
}

/* Port of SetMapTextPointer in home/predef_text.asm. */
__attribute__((noinline, used)) void
port_set_map_text_pointer(struct register_memory_state *state)
{
	state->registers.a = state->memory[0];
	state->memory[2] = state->registers.a;
	state->registers.a = state->memory[1];
	state->memory[3] = state->registers.a;
	state->registers.a = state->registers.l;
	state->memory[0] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[1] = state->registers.a;
}

/* Port of SaveEndBattleTextPointers in home/trainers.asm. */
__attribute__((noinline, used)) void
port_save_end_battle_text_pointers(struct register_memory_state *state)
{
	state->registers.a = state->memory[0];
	state->memory[1] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[2] = state->registers.a;
	state->registers.a = state->registers.l;
	state->memory[3] = state->registers.a;
	state->registers.a = state->registers.d;
	state->memory[4] = state->registers.a;
	state->registers.a = state->registers.e;
	state->memory[5] = state->registers.a;
}

/* Port of GetSavedEndBattleTextPointer in home/trainers.asm. */
__attribute__((noinline, used)) void
port_get_saved_end_battle_text_pointer(struct register_memory_state *state)
{
	port_u8 lost = state->memory[0];
	port_u8 base = lost == 0 ? 1 : 3;

	state->registers.a = lost;
	state->registers.f = PORT_FLAG_H;
	if (lost == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->memory[base];
	state->registers.h = state->registers.a;
	state->registers.a = state->memory[base + 1];
	state->registers.l = state->registers.a;
}

/* Port of GetPredefRegisters in home/predef.asm. */
__attribute__((noinline, used)) void
port_get_predef_registers(struct register_memory_state *state)
{
	state->registers.a = state->memory[0];
	state->registers.h = state->registers.a;
	state->registers.a = state->memory[1];
	state->registers.l = state->registers.a;
	state->registers.a = state->memory[2];
	state->registers.d = state->registers.a;
	state->registers.a = state->memory[3];
	state->registers.e = state->registers.a;
	state->registers.a = state->memory[4];
	state->registers.b = state->registers.a;
	state->registers.a = state->memory[5];
	state->registers.c = state->registers.a;
}

/* Port of DivideBCDPredef3's GetPredefRegisters wrapper. */
__attribute__((noinline, used)) void
port_divide_bcd_predef3(struct register_memory_state *state)
{
	port_get_predef_registers(state);
}

/* Port of ResetSpriteBufferPointers in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_reset_sprite_buffer_pointers(struct register_memory_state *state)
{
	port_u16 de;
	port_u16 hl;
	port_u8 flags = state->registers.f & PORT_FLAG_C;

	state->registers.a = state->memory[0];
	flags |= PORT_FLAG_H;
	if ((state->registers.a & 1) == 0)
		flags |= PORT_FLAG_Z;
	state->registers.f = flags;
	if ((state->registers.a & 1) == 0) {
		de = 0xa188;
		hl = 0xa310;
	} else {
		de = 0xa310;
		hl = 0xa188;
	}
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->registers.l;
	state->memory[1] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[2] = state->registers.a;
	state->registers.a = state->registers.e;
	state->memory[3] = state->registers.a;
	state->registers.a = state->registers.d;
	state->memory[4] = state->registers.a;
}

static port_u8
add_flags(port_u8 left, port_u8 right)
{
	port_u16 wide = (port_u16)left + right;
	port_u8 result = (port_u8)wide;
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		flags |= PORT_FLAG_H;
	if (wide > 0xff)
		flags |= PORT_FLAG_C;
	return flags;
}

static void
move_tile_pointer(struct register_memory_state *state, port_u8 operation)
{
	port_u8 low = state->memory[0];
	port_u8 high;
	port_u8 amount = 1;
	port_u16 de;

	if (operation >= 2) {
		state->registers.f = add_flags(state->registers.a, 6);
		state->registers.a += 6;
		state->registers.b = state->registers.a;
		amount = state->registers.b;
	}
	state->registers.a = low;
	if (operation == 0 || operation == 2) {
		state->registers.f = add_flags(low, amount);
		state->registers.a = (port_u8)(low + amount);
	} else {
		state->registers.f = cp_flags(low, amount);
		state->registers.a = (port_u8)(low - amount);
	}
	state->memory[0] = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) == 0)
		return;
	de = ((port_u16)state->registers.d << 8) | state->registers.e;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	high = state->memory[1];
	state->registers.a = high;
	if (operation == 0 || operation == 2) {
		state->registers.a++;
		state->registers.f = inc_flags(
			high, state->registers.a, PORT_FLAG_C);
	} else {
		state->registers.a--;
		state->registers.f = dec_flags(
			high, state->registers.a, PORT_FLAG_C);
	}
	state->memory[1] = state->registers.a;
}

__attribute__((noinline, used)) void
port_move_tile_block_map_pointer_east(struct register_memory_state *state)
{
	move_tile_pointer(state, 0);
}

__attribute__((noinline, used)) void
port_move_tile_block_map_pointer_west(struct register_memory_state *state)
{
	move_tile_pointer(state, 1);
}

__attribute__((noinline, used)) void
port_move_tile_block_map_pointer_south(struct register_memory_state *state)
{
	move_tile_pointer(state, 2);
}

__attribute__((noinline, used)) void
port_move_tile_block_map_pointer_north(struct register_memory_state *state)
{
	move_tile_pointer(state, 3);
}

/* Port of TownMapCoordsToOAMCoords in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_town_map_coords_to_oam_coords(struct register_memory_state *state)
{
	port_u8 packed = state->registers.a;
	port_u8 y = (port_u8)((packed & 0xf0) >> 1);
	port_u8 x = (port_u8)((packed & 0x0f) << 3);
	port_u16 hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;

	state->registers.b = (port_u8)(y + 24);
	state->memory[0] = state->registers.b;
	state->registers.a = (port_u8)(x + 24);
	state->registers.f = add_flags(x, 24);
	state->registers.c = state->registers.a;
	state->memory[1] = state->registers.a;
	hl += 2;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
