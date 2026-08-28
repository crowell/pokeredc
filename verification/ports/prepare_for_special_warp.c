#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_TILESET 0xd367u
#define W_LAST_MAP 0xd365u
#define W_LAST_BLACKOUT_MAP 0xd719u
#define W_DESTINATION_MAP 0xd71au
#define W_DESTINATION_WARP_ID 0xd42fu
#define W_Y_OFFSET_SPECIAL 0xd370u
#define W_X_OFFSET_SPECIAL 0xd371u
#define W_STATUS_FLAGS3 0xd72du
#define W_STATUS_FLAGS6 0xd732u
#define H_SERIAL_CONNECTION_STATUS 0xffaau

#define BIT_DEBUG_MODE 1u
#define BIT_FLY_OR_DUNGEON_WARP 2u
#define BIT_DUNGEON_WARP 4u
#define PALLET_TOWN 0x00u

void port_load_special_warp_data(struct special_warp_state *, port_u8 *);
void port_load_tileset_header(struct cpu_register_state *, port_u8 *);
struct prepare_new_game_debug_private_state {
	struct cpu_register_state registers;
};
void port_prepare_new_game_debug_private(
	struct prepare_new_game_debug_private_state *);

static void
bit_memory(struct cpu_register_state *r, port_u8 value, port_u8 bit)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((value & (port_u8)(1u << bit)) == 0)
		r->f |= PORT_FLAG_Z;
}

static void
and_a(struct cpu_register_state *r, port_u8 value)
{
	r->a = value;
	r->f = PORT_FLAG_H;
	if (value == 0)
		r->f |= PORT_FLAG_Z;
}

/* Port of PrepareForSpecialWarp in engine/overworld/special_warps.asm. */
__attribute__((noinline, used)) void
port_prepare_for_special_warp(struct cpu_register_state *r, port_u8 *memory)
{
	struct special_warp_state warp = {0};
	struct prepare_new_game_debug_private_state debug = {0};

	warp.registers = *r;
	warp.cable_destination = memory[W_STATUS_FLAGS3];
	warp.serial_status = memory[H_SERIAL_CONNECTION_STATUS];
	warp.status6 = memory[W_STATUS_FLAGS6];
	warp.status3 = memory[W_STATUS_FLAGS3];
	warp.last_map = memory[W_LAST_MAP];
	warp.last_blackout_map = memory[W_LAST_BLACKOUT_MAP];
	warp.destination_map = memory[W_DESTINATION_MAP];
	warp.dungeon_destination = memory[0xd71du];
	warp.which_dungeon_warp = memory[0xd71eu];
	warp.current_map = memory[W_CUR_MAP];
	warp.current_tileset = memory[W_CUR_MAP_TILESET];
	port_load_special_warp_data(&warp, memory);
	*r = warp.registers;
	memory[W_Y_OFFSET_SPECIAL] = warp.y_offset;
	memory[W_X_OFFSET_SPECIAL] = warp.x_offset;
	memory[W_DESTINATION_WARP_ID] = warp.destination_warp_id;
	port_load_tileset_header(r, memory);

	/* The predef returns with HL and the caller's registers restored; its
	 * observable work is in the map/tileset globals. */
	warp.registers = *r;
	warp.status6 = memory[W_STATUS_FLAGS6];
	warp.status3 = memory[W_STATUS_FLAGS3];
	warp.current_tileset = memory[W_CUR_MAP_TILESET];

	/* The assembly keeps HL pointed at wStatusFlags6 for the bit tests. */
	r->h = (port_u8)(W_STATUS_FLAGS6 >> 8);
	r->l = (port_u8)W_STATUS_FLAGS6;
	bit_memory(r, warp.status6, BIT_FLY_OR_DUNGEON_WARP);
	memory[W_STATUS_FLAGS6] &= (port_u8)~(1u << BIT_FLY_OR_DUNGEON_WARP);
	if ((warp.status6 & (1u << BIT_FLY_OR_DUNGEON_WARP)) != 0) {
		r->a = memory[W_DESTINATION_MAP];
	} else {
		bit_memory(r, memory[W_STATUS_FLAGS6], BIT_DEBUG_MODE);
		if ((memory[W_STATUS_FLAGS6] & (1u << BIT_DEBUG_MODE)) != 0) {
			port_prepare_new_game_debug_private(&debug);
		}
		r->a = PALLET_TOWN;
	}

	r->b = r->a;
	and_a(r, memory[W_STATUS_FLAGS3]);
	if (memory[W_STATUS_FLAGS3] == 0)
		r->a = r->b;

	bit_memory(r, memory[W_STATUS_FLAGS6], BIT_DUNGEON_WARP);
	if ((memory[W_STATUS_FLAGS6] & (1u << BIT_DUNGEON_WARP)) != 0)
		return;
	memory[W_LAST_MAP] = r->a;
}
