#include "joypad_port.h"

#define CELADON_PRIZE_MENU_BANK 0x14u
#define CELADON_PRIZE_MENU 0x671bu
#define BANKSWITCH_RETURN_H 0x35u
#define BANKSWITCH_RETURN_L 0xe4u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_bankswitch(struct bankswitch_state *,
	const struct cpu_register_state *, const port_u8[2]);
void port_hold_text_display_open(struct hold_text_display_open_state *,
	port_u8 *);

/* Port of TextScript_GameCornerPrizeMenu in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_text_script_game_corner_prize_menu(
	struct text_script_game_corner_prize_menu_state *state, port_u8 *memory)
{
	struct bankswitch_state bankswitch = {0};
	struct hold_text_display_open_state hold = {0};

	state->registers.b = CELADON_PRIZE_MENU_BANK;
	state->registers.h = (port_u8)(CELADON_PRIZE_MENU >> 8);
	state->registers.l = (port_u8)CELADON_PRIZE_MENU;

	/* Bankswitch's indirect JP enters CeladonPrizeMenu with this setup. */
	state->callback_call[0] = CELADON_PRIZE_MENU_BANK;
	state->callback_call[1] = state->registers.f;
	state->callback_call[2] = BANKSWITCH_RETURN_H;
	state->callback_call[3] = BANKSWITCH_RETURN_L;
	state->callback_call[4] = state->registers.d;
	state->callback_call[5] = state->registers.e;
	state->callback_call[6] = (port_u8)(CELADON_PRIZE_MENU >> 8);
	state->callback_call[7] = (port_u8)CELADON_PRIZE_MENU;
	state->callback_call[8] = CELADON_PRIZE_MENU_BANK;
	state->callback_call[9] = CELADON_PRIZE_MENU_BANK;

	bankswitch.registers = state->registers;
	bankswitch.loaded_rom_bank = state->loaded_rom_bank;
	bankswitch.mapper_bank = state->mapper_bank;
	port_u8 callback_banks[2] = {
		state->callback_loaded_rom_bank,
		state->callback_mapper_bank,
	};
	port_bankswitch(&bankswitch, &state->callback_registers, callback_banks);
	state->registers = bankswitch.registers;
	state->loaded_rom_bank = bankswitch.loaded_rom_bank;
	state->mapper_bank = bankswitch.mapper_bank;

	hold.registers = state->registers;
	for (port_u8 i = 0; i < 8u; ++i)
		hold.joy_inputs[i] = state->joy_inputs[i];
	hold.joy_input_count = state->joy_input_count;
	port_hold_text_display_open(&hold, memory);
	state->registers = hold.registers;
}
