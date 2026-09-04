#include "port_state.h"

void port_far_copy_data2(struct far_copy_data2_state *, port_u8 *);

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define INTRO_GRAPHICS_BANK 0x10u
#define FIGHT_INTRO_BACK_MON 0x5a99u
#define GAME_FREAK_INTRO 0x5959u
#define FIGHT_INTRO_FRONT_MON 0x6099u
#define VCHARS0 0x8000u
#define VCHARS1 0x8800u
#define VCHARS2 0x9000u
#define FIGHT_INTRO_BACK_MON_SIZE 0x600u
#define GAME_FREAK_INTRO_SIZE 0x140u
#define FIGHT_INTRO_FRONT_MON_SIZE 0x6c0u

static void
load_intro_graphics_copy(struct cpu_register_state *registers,
	port_u8 *memory, port_u16 source, port_u16 destination,
	port_u16 size)
{
	struct far_copy_data2_state copy = {0};

	registers->h = (port_u8)(source >> 8);
	registers->l = (port_u8)source;
	registers->d = (port_u8)(destination >> 8);
	registers->e = (port_u8)destination;
	registers->b = (port_u8)(size >> 8);
	registers->c = (port_u8)size;
	registers->a = INTRO_GRAPHICS_BANK;
	copy.registers = *registers;
	copy.loaded_bank = memory[H_LOADED_ROM_BANK];
	copy.rom_bank = memory[R_ROMB];
	port_far_copy_data2(&copy, memory);
	*registers = copy.registers;
	memory[H_LOADED_ROM_BANK] = copy.loaded_bank;
	memory[R_ROMB] = copy.rom_bank;
}

/* Port of LoadIntroGraphics in engine/movie/intro.asm. Each transfer is the
 * real proven FarCopyData2 transition; the final call is the tail return. */
__attribute__((noinline, used)) void
port_load_intro_graphics(struct cpu_register_state *state, port_u8 *memory)
{
	load_intro_graphics_copy(state, memory, FIGHT_INTRO_BACK_MON, VCHARS2,
		FIGHT_INTRO_BACK_MON_SIZE);
	load_intro_graphics_copy(state, memory, GAME_FREAK_INTRO,
		(port_u16)(VCHARS2 + FIGHT_INTRO_BACK_MON_SIZE),
		GAME_FREAK_INTRO_SIZE);
	load_intro_graphics_copy(state, memory, GAME_FREAK_INTRO, VCHARS1,
		GAME_FREAK_INTRO_SIZE);
	load_intro_graphics_copy(state, memory, FIGHT_INTRO_FRONT_MON, VCHARS0,
		FIGHT_INTRO_FRONT_MON_SIZE);
}
