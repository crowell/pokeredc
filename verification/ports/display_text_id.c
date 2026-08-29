#include "port_state.h"

#define W_TEXT_PREDEF_FLAG 0xcf11u
#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_TEXT_PTR 0xd36cu
#define W_SPRITE_INDEX 0xcf13u
#define H_TEXT_ID 0xff8cu
#define H_FRAME_COUNTER 0xffd5u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define BIT_TEXT_PREDEF 0u
#define TEXT_MON_FAINTED 0xd0u
#define PORT_FLAG_Z 0x80u
#define PORT_FLAG_N 0x40u

void port_display_text_id_init(
	struct display_text_id_init_private_state *, port_u8 *);
void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);

static port_u16
read_word(const port_u8 *memory, port_u16 address)
{
	return (port_u16)(memory[address] |
		((port_u16)memory[(port_u16)(address + 1u)] << 8));
}

/* Port of the initialization prefix of DisplayTextID in home/text_script.asm.
 * The subsequent text-ID/sprite/script dispatch remains a separate boundary;
 * this entry establishes exactly the state consumed by that dispatcher. */
__attribute__((noinline, used)) void
port_display_text_id(struct display_text_id_state *state, port_u8 *memory)
{
	struct display_text_id_init_private_state init = {0};
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->registers.f;
	port_u8 saved_e = state->registers.e;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = memory[R_ROMB];

	/* farcall DisplayTextIDInit (bank 1), including its complete proven body. */
	init.registers = state->registers;
	init.registers.b = 1u;
	init.registers.h = 0x70u;
	init.registers.l = 0x96u;
	port_display_text_id_init(&init, memory);
	state->registers = init.registers;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = state->mapper_bank;
	state->registers.a = saved_bank;
	state->registers.f = saved_f;
	/* Bankswitch returns the caller's saved AF through BC. */
	state->registers.b = saved_bank;
	state->registers.c = saved_f;
	state->registers.e = saved_e;

	if ((memory[W_TEXT_PREDEF_FLAG] & (1u << BIT_TEXT_PREDEF)) != 0u) {
		memory[W_TEXT_PREDEF_FLAG] &= (port_u8)~(1u << BIT_TEXT_PREDEF);
	} else {
		struct switch_to_map_rom_bank_state map = {0};
		map.registers = state->registers;
		map.registers.a = memory[W_CUR_MAP];
		map.loaded_rom_bank = saved_bank;
		map.mapper_bank = state->mapper_bank;
		port_switch_to_map_rom_bank(&map);
		state->registers = map.registers;
		state->loaded_rom_bank = map.loaded_rom_bank;
		state->mapper_bank = map.mapper_bank;
		memory[H_LOADED_ROM_BANK] = map.loaded_rom_bank;
		memory[R_ROMB] = map.mapper_bank;
	}

	memory[H_FRAME_COUNTER] = 30u;
	{
		port_u16 text = read_word(memory, W_CUR_MAP_TEXT_PTR);
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
	}
	state->registers.d = 0u;
	state->registers.a = memory[H_TEXT_ID];
	memory[W_SPRITE_INDEX] = state->registers.a;
	state->registers.f = state->registers.a == 0u ? PORT_FLAG_Z : 0u;
	/* The first dictionary branch is a cheap, fully bounded dispatch seam:
	 * CP TEXT_MON_FAINTED / JP z, DisplayPokemonFaintedText.  The handler and
	 * shared continuation are independently proven, so this entry records the
	 * exact compare result and leaves the callee body at its proof boundary. */
	if (state->registers.a == TEXT_MON_FAINTED)
		state->registers.f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);
}
