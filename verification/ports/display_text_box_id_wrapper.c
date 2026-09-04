#include "port_state.h"

#define DISPLAY_TEXT_BOX_ID_BANK 1u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_display_text_box_id(struct cpu_register_state *, port_u8 *);

/* Port of the home-bank DisplayTextBoxID wrapper in home/textbox.asm. */
__attribute__((noinline, used)) void
port_display_text_box_id_wrapper(struct display_text_box_id_state *state,
	port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->registers.f;

	/* homecall_sf DisplayTextBoxID_: select bank 1 while preserving AF in
	 * the stack word that returns through BC. */
	state->registers.a = DISPLAY_TEXT_BOX_ID_BANK;
	memory[H_LOADED_ROM_BANK] = DISPLAY_TEXT_BOX_ID_BANK;
	memory[R_ROMB] = DISPLAY_TEXT_BOX_ID_BANK;
	port_display_text_box_id(&state->registers, memory);

	state->registers.b = saved_bank;
	state->registers.c = saved_f;
	state->registers.a = saved_bank;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = saved_bank;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
}
