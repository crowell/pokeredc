#include "port_state.h"

#define W_PREDEF_PARENT_BANK 0xcf12u
#define H_LOADED_ROM_BANK 0xffb8u
#define W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER 0xd35fu
#define R_ROMB 0x2000u

void port_copy_data(struct cpu_register_state *, port_u8 *);

/* Port of LoadDestinationWarpPosition in home/overworld.asm. */
__attribute__((noinline, used)) void
port_load_destination_warp_position(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_a = saved_bank;
	port_u8 saved_f = registers->f;
	port_u16 source = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	port_u16 destination;
	struct cpu_register_state copy = *registers;

	memory[H_LOADED_ROM_BANK] = memory[W_PREDEF_PARENT_BANK];
	memory[R_ROMB] = memory[H_LOADED_ROM_BANK];
	source = (port_u16)(source + (port_u16)registers->a * 4u);
	destination = W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER;
	copy.h = (port_u8)(source >> 8);
	copy.l = (port_u8)source;
	copy.b = 0;
	copy.c = 4;
	copy.d = (port_u8)(destination >> 8);
	copy.e = (port_u8)destination;
	port_copy_data(&copy, memory);
	*registers = copy;
	registers->a = saved_a;
	registers->f = saved_f;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
}
