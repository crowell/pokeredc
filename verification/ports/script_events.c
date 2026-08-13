#include "port_state.h"

static void
rival_lookup_compare(struct cpu_register_state *registers, port_u8 right)
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

__attribute__((noinline, used)) void
port_route22_get_rival_trainer_no_begin(
	struct rival_trainer_lookup_state *state)
{
	state->registers.a = state->starter;
	state->registers.b = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_route22_get_rival_trainer_no_step(
	struct rival_trainer_lookup_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched_key;
	hl++;
	rival_lookup_compare(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b)
		hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.a == state->registers.b;
}

__attribute__((noinline, used)) void
port_route22_get_rival_trainer_no_finish(
	struct rival_trainer_lookup_state *state)
{
	state->registers.a = state->fetched_value;
	state->trainer_no = state->registers.a;
}

/* Port of Route22GetRivalTrainerNoByStarterScript in scripts/Route22.asm. */
__attribute__((noinline, used)) void
port_route22_get_rival_trainer_no(
	struct rival_trainer_lookup_state *state, const port_u8 *memory)
{
	port_u16 hl;

	port_route22_get_rival_trainer_no_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_key = memory[hl];
	} while (!port_route22_get_rival_trainer_no_step(state));
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->fetched_value = memory[hl];
	port_route22_get_rival_trainer_no_finish(state);
}

static void
set_silph_door_event(
	struct event_bit_state *state, port_u16 address, port_u8 mask)
{
	state->registers.a = state->source;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	state->registers.h = (port_u8)(address >> 8);
	state->registers.l = (port_u8)address;
	state->event_byte |= mask;
}

__attribute__((noinline, used)) void
port_silph_co_6f_unlocked_door_event(struct event_bit_state *state)
{
	set_silph_door_event(state, 0xd82e, 0x80);
}

__attribute__((noinline, used)) void
port_silph_co_8f_unlocked_door_event(struct event_bit_state *state)
{
	set_silph_door_event(state, 0xd832, 0x01);
}

__attribute__((noinline, used)) void
port_silph_co_10f_set_unlocked_doors(struct event_bit_state *state)
{
	set_silph_door_event(state, 0xd836, 0x01);
}

__attribute__((noinline, used)) void
port_silph_co_11f_set_unlocked_door_event(struct event_bit_state *state)
{
	set_silph_door_event(state, 0xd838, 0x01);
}

/* Port of SSAnneCaptainsRoomEventScript. */
__attribute__((noinline, used)) void
port_ss_anne_captains_room_event(struct event_bit_state *state)
{
	state->registers.a = state->source;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->registers.a & 0x02) != 0)
		return;
	state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xd7;
	state->registers.l = 0x2d;
	state->event_byte |= 0x20;
}

static void
compare_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static port_u8
begin_multi_door_event(struct event_bit_state *state, port_u16 address)
{
	state->registers.h = (port_u8)(address >> 8);
	state->registers.l = (port_u8)address;
	state->registers.a = state->source;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return 0;
	}
	return 1;
}

static void
set_two_door_event(
	struct event_bit_state *state, port_u16 address,
	port_u8 first_mask, port_u8 second_mask)
{
	if (!begin_multi_door_event(state, address))
		return;
	compare_a(&state->registers, 1);
	state->event_byte |=
		state->registers.a == 1 ? first_mask : second_mask;
}

static void
set_three_door_event(
	struct event_bit_state *state, port_u16 address,
	port_u8 first_mask, port_u8 second_mask, port_u8 third_mask)
{
	if (!begin_multi_door_event(state, address))
		return;
	compare_a(&state->registers, 1);
	if (state->registers.a == 1) {
		state->event_byte |= first_mask;
		return;
	}
	compare_a(&state->registers, 2);
	state->event_byte |=
		state->registers.a == 2 ? second_mask : third_mask;
}

__attribute__((noinline, used)) void
port_silph_co_2f_unlocked_door_event(struct event_bit_state *state)
{
	set_two_door_event(state, 0xd826, 0x20, 0x40);
}

__attribute__((noinline, used)) void
port_silph_co_3f_unlocked_door_event(struct event_bit_state *state)
{
	set_two_door_event(state, 0xd828, 0x01, 0x02);
}

__attribute__((noinline, used)) void
port_silph_co_4f_unlocked_door_event(struct event_bit_state *state)
{
	set_two_door_event(state, 0xd82a, 0x01, 0x02);
}

__attribute__((noinline, used)) void
port_silph_co_5f_set_unlocked_doors(struct event_bit_state *state)
{
	set_three_door_event(state, 0xd82c, 0x01, 0x02, 0x04);
}

__attribute__((noinline, used)) void
port_silph_co_7f_unlocked_door_event(struct event_bit_state *state)
{
	set_three_door_event(state, 0xd830, 0x10, 0x20, 0x40);
}

__attribute__((noinline, used)) void
port_silph_co_9f_set_unlocked_doors(struct event_bit_state *state)
{
	port_u8 count;

	if (!begin_multi_door_event(state, 0xd834))
		return;
	for (count = 1; count <= 4; count++) {
		compare_a(&state->registers, count);
		if (state->registers.a == count) {
			state->event_byte |= (port_u8)(1 << (count - 1));
			return;
		}
	}
}

/* Port of OaksLabLoadTextPointers2Script. */
__attribute__((noinline, used)) void
port_oaks_lab_load_text_pointers2(struct memory_transfer_state *state)
{
	state->registers.h = 0x50;
	state->registers.l = 0xb8;
	state->registers.a = state->registers.l;
	state->memory[1] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[2] = state->registers.a;
}

/* Port of ViridianMartCheckParcelDeliveredScript. */
__attribute__((noinline, used)) void
port_viridian_mart_check_parcel_delivered(
	struct memory_transfer_state *state)
{
	state->registers.a = state->memory[0];
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((state->registers.a & 0x01) == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.h = 0x54;
		state->registers.l = 0xe0;
	} else {
		state->registers.h = 0x54;
		state->registers.l = 0xea;
	}
	state->registers.a = state->registers.l;
	state->memory[1] = state->registers.a;
	state->registers.a = state->registers.h;
	state->memory[2] = state->registers.a;
}

__attribute__((noinline, used)) void
port_silph_card_key_door_begin(struct card_key_door_state *state)
{
	state->registers.b = state->card_y;
	state->registers.a = state->card_x;
	state->registers.c = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->unlocked = 0;
}

__attribute__((noinline, used)) port_u8
port_silph_card_key_door_step(struct card_key_door_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old;

	state->registers.a = state->fetched_y;
	hl++;
	compare_a(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->unlocked = 0;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 2;
	}
	old = state->unlocked;
	state->unlocked++;
	state->registers.f &= PORT_FLAG_C;
	if (state->unlocked == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	compare_a(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b) {
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	state->registers.a = state->fetched_x;
	hl++;
	compare_a(&state->registers, state->registers.c);
	if (state->registers.a != state->registers.c) {
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	state->registers.h = 0xd7;
	state->registers.l = 0x3f;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->card_y = 0;
	state->registers.l++;
	state->card_x = 0;
	return 1;
}

static void
silph_card_key_door(
	struct card_key_door_state *state, const port_u8 *memory)
{
	port_u16 hl;
	port_u8 result;

	port_silph_card_key_door_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_y = memory[hl];
		if (state->fetched_y != 0xff &&
			state->fetched_y == state->registers.b)
			state->fetched_x = memory[(port_u16)(hl + 1)];
		result = port_silph_card_key_door_step(state);
	} while (result == 0);
}

#define CARD_KEY_DOOR_WRAPPER(name) \
	__attribute__((noinline, used)) void name( \
		struct card_key_door_state *state, const port_u8 *memory) \
	{ \
		silph_card_key_door(state, memory); \
	}

CARD_KEY_DOOR_WRAPPER(port_silph_co_2f_set_card_key_door_y)
CARD_KEY_DOOR_WRAPPER(port_silph_co_4f_set_card_key_door_y)
CARD_KEY_DOOR_WRAPPER(port_silph_co_7f_set_card_key_door_y)
CARD_KEY_DOOR_WRAPPER(port_silph_co_8f_set_card_key_door_y)
CARD_KEY_DOOR_WRAPPER(port_silph_co_9f_set_card_key_door_y)
CARD_KEY_DOOR_WRAPPER(port_silph_co_11f_set_card_key_door_y)

static void
store_elevator_warp_entries(struct elevator_warp_state *state)
{
	state->registers.h = 0xd3;
	state->registers.l = 0xaf;
	state->registers.a = state->source_warp;
	state->registers.b = state->registers.a;
	state->registers.a = state->source_map;
	state->registers.c = state->registers.a;
	state->registers.l += 2;
	state->registers.a = state->registers.b;
	state->destinations[0] = state->registers.a;
	state->registers.l++;
	state->registers.a = state->registers.c;
	state->destinations[1] = state->registers.a;
	state->registers.l++;
	state->registers.l += 2;
	state->registers.a = state->registers.b;
	state->destinations[2] = state->registers.a;
	state->registers.l++;
	state->registers.a = state->registers.c;
	state->destinations[3] = state->registers.a;
	state->registers.l++;
}

#define ELEVATOR_WARP_WRAPPER(name) \
	__attribute__((noinline, used)) void name( \
		struct elevator_warp_state *state) \
	{ \
		store_elevator_warp_entries(state); \
	}

ELEVATOR_WARP_WRAPPER(port_celadon_mart_elevator_store_warp_entries)
ELEVATOR_WARP_WRAPPER(port_rocket_hideout_elevator_store_warp_entries)
ELEVATOR_WARP_WRAPPER(port_silph_co_elevator_store_warp_entries)
