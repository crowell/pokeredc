#include "port_state.h"

#define W_NUMBER_OF_WARPS 0xd3aeu
#define W_WARP_ENTRIES 0xd3afu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_DESTINATION_WARP_ID 0xd42fu
#define H_WARP_DESTINATION_MAP 0xff8bu
#define W_MOVEMENT_FLAGS 0xd736u
#define W_MAP_PAL_OFFSET 0xd35du
#define R_BGP 0xff47u
#define R_OBP0 0xff48u
#define R_OBP1 0xff49u
#define FADE_PAL4 0x2116u

void port_gb_fade_in_from_white(struct cpu_register_state *, port_u8 *);
void port_is_player_standing_on_warp(struct standing_on_warp_state *,
	const port_u8 *);
void port_load_gb_pal(struct load_gb_pal_state *);

/* Port of MapEntryAfterBattle in home/overworld.asm. */
__attribute__((noinline, used)) void
port_map_entry_after_battle(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct standing_on_warp_state warp;

	warp.registers = *registers;
	warp.number_of_warps = memory[W_NUMBER_OF_WARPS];
	warp.y = memory[W_Y_COORD];
	warp.x = memory[W_X_COORD];
	warp.destination_warp = memory[W_DESTINATION_WARP_ID];
	warp.destination_map = memory[H_WARP_DESTINATION_MAP];
	warp.movement_flags = memory[W_MOVEMENT_FLAGS];
	port_is_player_standing_on_warp(&warp, &memory[W_WARP_ENTRIES]);
	*registers = warp.registers;
	memory[W_DESTINATION_WARP_ID] = warp.destination_warp;
	memory[H_WARP_DESTINATION_MAP] = warp.destination_map;
	memory[W_MOVEMENT_FLAGS] = warp.movement_flags;

	registers->a = memory[W_MAP_PAL_OFFSET];
	registers->f = PORT_FLAG_H | (registers->a == 0 ? PORT_FLAG_Z : 0);
	if (registers->f & PORT_FLAG_Z) {
		port_gb_fade_in_from_white(registers, memory);
		return;
	}

	{
		struct load_gb_pal_state palette;
		port_u16 source = (port_u16)(FADE_PAL4 - registers->a);

		palette.registers = *registers;
		palette.map_pal_offset = registers->a;
		palette.fetched[0] = memory[source];
		palette.fetched[1] = memory[(port_u16)(source + 1)];
		palette.fetched[2] = memory[(port_u16)(source + 2)];
		port_load_gb_pal(&palette);
		*registers = palette.registers;
		memory[R_BGP] = palette.background_palette;
		memory[R_OBP0] = palette.object_palette0;
		memory[R_OBP1] = palette.object_palette1;
	}
}
