#include "joypad_port.h"

#define REPEL_WORE_OFF_TEXT 0x2ac8u

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_after_displaying_text_id(
	struct after_displaying_text_id_state *, port_u8 *);

/* Port of DisplayRepelWoreOffText in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_repel_wore_off_text(
	struct display_repel_wore_off_text_state *state, port_u8 *memory)
{
	struct after_displaying_text_id_state after = {0};

	/* ld hl, RepelWoreOffText */
	state->registers.h = (port_u8)(REPEL_WORE_OFF_TEXT >> 8);
	state->registers.l = (port_u8)REPEL_WORE_OFF_TEXT;

	after.registers = state->registers;
	for (port_u8 i = 0; i < 8u; ++i)
		after.joy_inputs[i] = state->joy_inputs[i];
	after.joy_input_count = state->joy_input_count;
	port_print_text(&after.registers, memory);
	port_after_displaying_text_id(&after, memory);
	state->registers = after.registers;
}
