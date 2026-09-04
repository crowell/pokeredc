#include "joypad_port.h"

#define PRINT_SAFARI_GAME_OVER_TEXT 0x69edu
#define PRINT_SAFARI_GAME_OVER_TEXT_BANK 7u

void port_print_safari_game_over_text_private(
	struct cpu_register_state *, port_u8 *);
void port_after_displaying_text_id(
	struct after_displaying_text_id_state *, port_u8 *);

/* Port of DisplaySafariGameOverText in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_safari_game_over_text(
	struct display_safari_game_over_text_state *state, port_u8 *memory)
{
	struct after_displaying_text_id_state after = {0};
	port_u8 saved_a = state->registers.a;
	port_u8 saved_f = state->registers.f;

	/* callfar PrintSafariGameOverText */
	after.registers = state->registers;
	after.registers.h = (port_u8)(PRINT_SAFARI_GAME_OVER_TEXT >> 8);
	after.registers.l = (port_u8)PRINT_SAFARI_GAME_OVER_TEXT;
	after.registers.b = PRINT_SAFARI_GAME_OVER_TEXT_BANK;
	port_print_safari_game_over_text_private(&after.registers, memory);

	/* Bankswitch carries the saved AF bytes through BC before returning. */
	after.registers.a = saved_a;
	after.registers.b = saved_a;
	after.registers.c = saved_f;

	for (port_u8 i = 0; i < 8u; ++i)
		after.joy_inputs[i] = state->joy_inputs[i];
	after.joy_input_count = state->joy_input_count;
	port_after_displaying_text_id(&after, memory);
	state->registers = after.registers;
}
