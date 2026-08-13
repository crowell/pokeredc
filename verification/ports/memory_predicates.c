#include "port_state.h"

/* Port of SafariZoneGateReturnSimulatedJoypadStateScript. */
__attribute__((noinline, used)) void
port_safari_zone_gate_return_simulated_joypad_state_script(
	struct memory_predicate_state *state)
{
	state->registers.a = state->value;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}

/* Port of CheckIfInOutsideMap in home/overworld.asm. */
__attribute__((noinline, used)) void
port_check_if_in_outside_map(struct memory_predicate_state *state)
{
	port_u8 value = state->value;

	state->registers.a = value;
	state->registers.f = PORT_FLAG_H;
	if (value == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}

	state->registers.f = PORT_FLAG_N;
	if (value == 0x17)
		state->registers.f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 0x07)
		state->registers.f |= PORT_FLAG_H;
	if (value < 0x17)
		state->registers.f |= PORT_FLAG_C;
}

/* Port of GetSelectedMoveOffset2 in engine/items/item_effects.asm. */
__attribute__((noinline, used)) void
port_get_selected_move_offset2(struct memory_predicate_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u16 offset = state->value;
	unsigned long wide = (unsigned long)hl + offset;
	port_u8 flags = state->registers.f & PORT_FLAG_Z;

	state->registers.a = state->value;
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	if ((hl & 0x0fff) + offset > 0x0fff)
		flags |= PORT_FLAG_H;
	if (wide > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(wide >> 8);
	state->registers.l = (port_u8)wide;
}

__attribute__((noinline, used)) port_u8
port_trainer_info_next_text_box_row_step(struct memory_predicate_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 previous_a;

	hl++;
	previous_a = state->registers.a;
	state->registers.a--;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((previous_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.a == 0;
}

/* Port of TrainerInfo_NextTextBoxRow in engine/menus/start_sub_menus.asm. */
__attribute__((noinline, used)) void
port_trainer_info_next_text_box_row(struct memory_predicate_state *state)
{
	state->registers.a = state->value;
	while (!port_trainer_info_next_text_box_row_step(state))
		;
}

/* Return nonzero for the PrintButItFailedText_ tail continuation. */
__attribute__((noinline, used)) port_u8
port_conditional_print_but_it_failed(struct memory_predicate_state *state)
{
	state->registers.a = state->value;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return 1;
	}
	return 0;
}

/* Port of GetSpriteMovementByte1Pointer in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_get_sprite_movement_byte1_pointer(struct memory_predicate_state *state)
{
	port_u8 left;
	port_u8 result;
	port_u8 flags = 0;

	state->registers.h = 0xc2;
	state->registers.a = state->value;
	state->registers.a = (port_u8)(
		(state->registers.a << 4) | (state->registers.a >> 4));
	left = state->registers.a;
	result = (port_u8)(left + 6);
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) + 6 > 0x0f)
		flags |= PORT_FLAG_H;
	if ((port_u16)left + 6 > 0xff)
		flags |= PORT_FLAG_C;
	state->registers.a = result;
	state->registers.f = flags;
	state->registers.l = result;
}

/* Port of GetSpriteMovementByte2Pointer in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_get_sprite_movement_byte2_pointer(struct memory_predicate_state *state)
{
	port_u8 index = state->value;
	port_u8 decremented = (port_u8)(index - 1);
	port_u8 offset = (port_u8)(decremented + decremented);
	port_u16 hl = (port_u16)(0xd4e4 + offset);
	port_u8 flags = 0;

	state->registers.a = offset;
	if (offset == 0)
		flags |= PORT_FLAG_Z;
	if ((decremented & 0x0f) + (decremented & 0x0f) > 0x0f)
		flags |= PORT_FLAG_H;
	if ((port_u16)decremented * 2 > 0xff)
		flags |= PORT_FLAG_C;
	/* ADD HL,DE preserves Z from ADD A but replaces H and C. */
	flags &= PORT_FLAG_Z;
	if ((0xd4e4 & 0x0fff) + offset > 0x0fff)
		flags |= PORT_FLAG_H;
	if ((unsigned long)0xd4e4 + offset > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Port of GetSpriteDataPointer in engine/overworld/trainer_sight.asm. */
__attribute__((noinline, used)) void
port_get_sprite_data_pointer(struct memory_predicate_state *state)
{
	port_u16 initial_hl = ((port_u16)state->registers.h << 8) |
		state->registers.l;
	port_u16 initial_de = ((port_u16)state->registers.d << 8) |
		state->registers.e;
	port_u8 swapped = (port_u8)((state->value << 4) | (state->value >> 4));
	port_u16 intermediate = initial_hl + initial_de;
	port_u16 result = intermediate + swapped;
	port_u8 flags = 0;

	state->registers.a = swapped;
	if (swapped == 0)
		flags |= PORT_FLAG_Z;
	if ((intermediate & 0x0fff) + swapped > 0x0fff)
		flags |= PORT_FLAG_H;
	if ((unsigned long)intermediate + swapped > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
}

static port_u8
sight_cp_flags(port_u8 left, port_u8 right)
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

static void
sight_not_in_line(struct trainer_sight_state *state)
{
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}

/* Port of CheckSpriteCanSeePlayer in engine/overworld/trainer_sight.asm. */
__attribute__((noinline, used)) void
port_check_sprite_can_see_player(struct trainer_sight_state *state)
{
	state->registers.b = state->registers.a;
	state->registers.a = state->engage_distance;
	state->registers.f = sight_cp_flags(
		state->registers.a, state->registers.b);
	if (state->registers.a < state->registers.b) {
		sight_not_in_line(state);
		return;
	}
	state->registers.a = state->facing_direction;
	if (state->registers.a == 0 || state->registers.a == 4) {
		state->registers.a = state->screen_x;
		state->registers.b = state->registers.a;
		state->registers.f = sight_cp_flags(state->registers.a, 0x40);
		if (state->registers.a == 0x40) {
			state->registers.f = PORT_FLAG_Z | PORT_FLAG_C;
			return;
		}
		sight_not_in_line(state);
		return;
	}
	if (state->registers.a == 8 || state->registers.a == 12) {
		state->registers.a = state->screen_y;
		state->registers.b = state->registers.a;
		state->registers.f = sight_cp_flags(state->registers.a, 0x3c);
		if (state->registers.a == 0x3c) {
			state->registers.f = PORT_FLAG_Z | PORT_FLAG_C;
			return;
		}
		sight_not_in_line(state);
		return;
	}
	sight_not_in_line(state);
}

/* Port of CheckTargetSubstitute in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_check_target_substitute(struct target_substitute_state *state)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 status;

	state->registers.h = 0xd0;
	state->registers.l = 0x68;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		status = state->enemy_status2;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x63;
		status = state->player_status2;
	}
	state->registers.f = PORT_FLAG_H;
	if ((status & 0x10) == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}

/* Port of GetHealthBarColor in home/palettes.asm. */
__attribute__((noinline, used)) void
port_get_health_bar_color(struct memory_predicate_state *state)
{
	state->registers.a = state->registers.e;
	state->registers.f = sight_cp_flags(state->registers.a, 27);
	state->registers.d = 0;
	if (state->registers.a < 27) {
		state->registers.f = sight_cp_flags(state->registers.a, 10);
		state->registers.d++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.a < 10) {
			state->registers.d++;
			state->registers.f &= PORT_FLAG_C;
		}
	}
	state->value = state->registers.d;
}
