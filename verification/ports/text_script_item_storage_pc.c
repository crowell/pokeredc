#include "joypad_port.h"

#define PLAYER_PC_BANK 1u
#define PLAYER_PC 0x78e6u
#define BANKSWITCH_RETURN_H 0x35u
#define BANKSWITCH_RETURN_L 0xe4u

void port_save_screen_tiles_to_buffer2(struct cpu_register_state *, port_u8 *);
void port_bankswitch(struct bankswitch_state *,
	const struct cpu_register_state *, const port_u8[2]);
void port_hold_text_display_open(struct hold_text_display_open_state *,
	port_u8 *);

/* Port of TextScript_ItemStoragePC in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_text_script_item_storage_pc(
	struct text_script_item_storage_pc_state *state, port_u8 *memory)
{
	struct bankswitch_state bankswitch = {0};
	struct hold_text_display_open_state hold = {0};

	port_save_screen_tiles_to_buffer2(&state->registers, memory);
	state->registers.b = PLAYER_PC_BANK;
	state->registers.h = (port_u8)(PLAYER_PC >> 8);
	state->registers.l = (port_u8)PLAYER_PC;

	/* Bankswitch's indirect JP enters PlayerPC with this setup. */
	state->callback_call[0] = PLAYER_PC_BANK;
	state->callback_call[1] = state->registers.f;
	state->callback_call[2] = BANKSWITCH_RETURN_H;
	state->callback_call[3] = BANKSWITCH_RETURN_L;
	state->callback_call[4] = state->registers.d;
	state->callback_call[5] = state->registers.e;
	state->callback_call[6] = (port_u8)(PLAYER_PC >> 8);
	state->callback_call[7] = (port_u8)PLAYER_PC;
	state->callback_call[8] = PLAYER_PC_BANK;
	state->callback_call[9] = PLAYER_PC_BANK;

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
