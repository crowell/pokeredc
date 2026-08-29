#include "port_state.h"

#define W_TEXT_PREDEF_FLAG 0xcf11u
#define W_CUR_MAP_TEXT_PTR 0xd36cu
#define H_TEXT_ID 0xff8cu
#define H_SAVED_MAP_TEXT_PTR 0xffecu
#define TEXT_PREDEFS 0x3f22u
#define BIT_TEXT_PREDEF 0u

void port_display_text_id(struct display_text_id_state *, port_u8 *);

/* Port of PrintPredefTextID in home/predef_text.asm. */
__attribute__((noinline, used)) void
port_print_predef_text_id(struct print_predef_text_id_state *state,
	port_u8 *memory)
{
	port_u8 saved_low = memory[W_CUR_MAP_TEXT_PTR];
	port_u8 saved_high = memory[W_CUR_MAP_TEXT_PTR + 1u];
	struct display_text_id_state display = {0};

	memory[H_TEXT_ID] = state->registers.a;
	memory[H_SAVED_MAP_TEXT_PTR] = saved_low;
	memory[H_SAVED_MAP_TEXT_PTR + 1u] = saved_high;
	memory[W_CUR_MAP_TEXT_PTR] = (port_u8)TEXT_PREDEFS;
	memory[W_CUR_MAP_TEXT_PTR + 1u] = (port_u8)(TEXT_PREDEFS >> 8);
	memory[W_TEXT_PREDEF_FLAG] |= (port_u8)(1u << BIT_TEXT_PREDEF);

	display.registers = state->registers;
	display.loaded_rom_bank = state->loaded_rom_bank;
	display.mapper_bank = state->mapper_bank;
	port_display_text_id(&display, memory);
	state->registers = display.registers;
	state->loaded_rom_bank = display.loaded_rom_bank;
	state->mapper_bank = display.mapper_bank;

	memory[W_CUR_MAP_TEXT_PTR] = memory[H_SAVED_MAP_TEXT_PTR];
	memory[W_CUR_MAP_TEXT_PTR + 1u] = memory[H_SAVED_MAP_TEXT_PTR + 1u];
	/* RestoreMapTextPointer leaves HL advanced past the low byte and A
	 * containing the restored high byte. */
	state->registers.h = (port_u8)(W_CUR_MAP_TEXT_PTR >> 8);
	state->registers.l = (port_u8)(W_CUR_MAP_TEXT_PTR + 1u);
	state->registers.a = memory[H_SAVED_MAP_TEXT_PTR + 1u];
}
