#include "joypad_port.h"

#define POKEMON_FAINTED_TEXT 0x2aa4u

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_after_displaying_text_id(
	struct after_displaying_text_id_state *, port_u8 *);

/* Port of DisplayPokemonFaintedText in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_pokemon_fainted_text(
	struct display_pokemon_fainted_text_state *state, port_u8 *memory)
{
	struct after_displaying_text_id_state after = {0};

	/* ld hl, PokemonFaintedText */
	state->registers.h = (port_u8)(POKEMON_FAINTED_TEXT >> 8);
	state->registers.l = (port_u8)POKEMON_FAINTED_TEXT;

	/* PrintText is a proven compositional boundary; its tail continuation
	 * leaves the text pointer in HL and establishes the message-box cursor. */
	after.registers = state->registers;
	port_print_text(&after.registers, memory);
	for (port_u8 i = 0; i < 8u; ++i)
		after.joy_inputs[i] = state->joy_inputs[i];
	after.joy_input_count = state->joy_input_count;

	/* The assembly tail-jumps into the shared text-display continuation. */
	port_after_displaying_text_id(&after, memory);
	state->registers = after.registers;
}
