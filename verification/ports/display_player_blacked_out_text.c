#include "joypad_port.h"

#define PLAYER_BLACKED_OUT_TEXT 0x2abau
#define W_STATUS_FLAGS6 0xd732u
#define BIT_ALWAYS_ON_BIKE 5u

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_hold_text_display_open(struct hold_text_display_open_state *,
	port_u8 *);

/* Port of DisplayPlayerBlackedOutText in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_player_blacked_out_text(
	struct display_player_blacked_out_text_state *state, port_u8 *memory)
{
	struct hold_text_display_open_state hold = {0};

	/* ld hl, PlayerBlackedOutText; call PrintText */
	state->registers.h = (port_u8)(PLAYER_BLACKED_OUT_TEXT >> 8);
	state->registers.l = (port_u8)PLAYER_BLACKED_OUT_TEXT;
	port_print_text(&state->registers, memory);

	/* res BIT_ALWAYS_ON_BIKE, a */
	state->registers.a = memory[W_STATUS_FLAGS6];
	state->registers.a &= (port_u8)~(1u << BIT_ALWAYS_ON_BIKE);
	memory[W_STATUS_FLAGS6] = state->registers.a;

	/* The assembly tail-jumps into HoldTextDisplayOpen. */
	hold.registers = state->registers;
	for (port_u8 i = 0; i < 8u; ++i)
		hold.joy_inputs[i] = state->joy_inputs[i];
	hold.joy_input_count = state->joy_input_count;
	port_hold_text_display_open(&hold, memory);
	state->registers = hold.registers;
}
