#include "port_state.h"

#include "joypad_port.h"

/* Port of IsSurfingAllowed in engine/overworld/field_move_messages.asm. */

port_u8 port_are_player_coords_in_array(
	struct are_player_coords_state *, const port_u8 *);
void port_print_text(struct cpu_register_state *, port_u8 *);

#define W_STATUS_FLAGS1 0xd728u
#define W_STATUS_FLAGS6 0xd732u
#define W_CUR_MAP 0xd35eu
#define W_EVENT_FLAGS 0xd747u
#define W_COORD_INDEX 0xcd3du
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_TEXT_BOX_ID 0xd125u
#define H_CURRENT_TOO_FAST_TEXT 0x4dfau
#define H_CYCLING_IS_FUN_TEXT 0x4dffu
#define STAIRS_COORDS 0x4df7u
#define STAIRS_EVENT_BYTE 0x13au
#define SEAFOAM_ISLANDS_B4F 0xa2u
#define BIT_SURF_ALLOWED 1u
#define BIT_ALWAYS_ON_BIKE 5u

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static void
clear_surf_allowed(port_u8 *memory)
{
	memory[W_STATUS_FLAGS1] &= (port_u8)~(1u << BIT_SURF_ALLOWED);
}

static void
print_surfing_message(struct cpu_register_state *state, port_u8 *memory,
	port_u16 text)
{
	state->h = (port_u8)(text >> 8);
	state->l = (port_u8)text;
	port_print_text(state, memory);
}

__attribute__((noinline, used)) void
port_is_surfing_allowed(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(W_STATUS_FLAGS1 >> 8);
	state->l = (port_u8)W_STATUS_FLAGS1;
	struct are_player_coords_state coords;
	static const port_u8 stairs[] = { 11u, 7u, 0xffu };
	port_u8 status6 = memory[W_STATUS_FLAGS6];
	port_u8 map;
	port_u8 events;
	port_u8 result;

	memory[W_STATUS_FLAGS1] |= (port_u8)(1u << BIT_SURF_ALLOWED);
	state->a = status6;
	state->f = (port_u8)((state->f & PORT_FLAG_C) |
		PORT_FLAG_H | ((status6 & (1u << BIT_ALWAYS_ON_BIKE)) == 0 ?
		PORT_FLAG_Z : 0));
	if ((status6 & (1u << BIT_ALWAYS_ON_BIKE)) != 0) {
		clear_surf_allowed(memory);
		print_surfing_message(state, memory, H_CYCLING_IS_FUN_TEXT);
		return;
	}

	map = memory[W_CUR_MAP];
	state->a = map;
	state->f = cp_flags(map, SEAFOAM_ISLANDS_B4F);
	if (map != SEAFOAM_ISLANDS_B4F)
		return;

	events = (port_u8)(memory[W_EVENT_FLAGS + STAIRS_EVENT_BYTE] & 0x03u);
	state->a = events;
	state->f = cp_flags(events, 0x03u);
	if (events == 0x03u)
		return;

	coords.check.registers = *state;
	coords.check.registers.h = 0;
	coords.check.registers.l = 0;
	coords.player_y = memory[W_Y_COORD];
	coords.player_x = memory[W_X_COORD];
	result = port_are_player_coords_in_array(&coords, stairs);
	*state = coords.check.registers;
	memory[W_COORD_INDEX] = coords.check.coord_index;
	state->h = (port_u8)(STAIRS_COORDS >> 8);
	state->l = (port_u8)(STAIRS_COORDS +
		(result == 2u ? 2u : 3u));
	if (result != 2u)
		return;

	clear_surf_allowed(memory);
	print_surfing_message(state, memory, H_CURRENT_TOO_FAST_TEXT);
}
