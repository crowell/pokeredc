#include "joypad_port.h"

#define DISPLAY_POKEMON_CENTER_DIALOGUE_BANK 1u

struct display_pokemon_center_dialogue_private_state;
void port_display_pokemon_center_dialogue_private(
	struct display_pokemon_center_dialogue_private_state *);
void port_after_displaying_text_id(
	struct after_displaying_text_id_state *, port_u8 *);

/* Port of DisplayPokemonCenterDialogue in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_pokemon_center_dialogue(
	struct display_pokemon_center_dialogue_state *state, port_u8 *memory)
{
	struct after_displaying_text_id_state after = {0};
	struct cpu_register_state private_registers;
	port_u8 saved_bank = state->loaded_rom_bank;

	/* xor a; clear the three-byte hItemPrice scratch value. */
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->item_price[0] = 0;
	state->item_price[1] = 0;
	state->item_price[2] = 0;

	/* inc hl (flags are preserved), then homecall DisplayPokemonCenterDialogue_. */
	{
		port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
	}
	private_registers = state->registers;
	state->loaded_rom_bank = DISPLAY_POKEMON_CENTER_DIALOGUE_BANK;
	state->romb = DISPLAY_POKEMON_CENTER_DIALOGUE_BANK;
	private_registers.a = DISPLAY_POKEMON_CENTER_DIALOGUE_BANK;
	port_display_pokemon_center_dialogue_private(
		(struct display_pokemon_center_dialogue_private_state *)&private_registers);
	state->registers = private_registers;

	/* homecall restores the caller's AF and ROM bank before the tail call. */
	state->registers.a = saved_bank;
	state->registers.f = PORT_FLAG_Z;
	state->loaded_rom_bank = saved_bank;
	state->romb = saved_bank;

	after.registers = state->registers;
	for (port_u8 i = 0; i < 8u; ++i)
		after.joy_inputs[i] = state->joy_inputs[i];
	after.joy_input_count = state->joy_input_count;
	port_after_displaying_text_id(&after, memory);
	state->registers = after.registers;
}
