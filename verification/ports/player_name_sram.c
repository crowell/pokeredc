#include "port_state.h"

/* Port of CheckForPlayerNameInSRAM in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_check_for_player_name_in_sram(struct player_name_sram_state *state)
{
	port_u16 hl = 0xa598;
	port_u8 index;
	port_u8 found = 0;

	state->registers.a = 0x0a;
	state->ram_enable = state->registers.a;
	state->registers.a = 1;
	state->bank_mode = state->registers.a;
	state->ram_bank = state->registers.a;
	state->registers.b = 11;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	for (index = 0; index < 11; index++) {
		state->registers.a = state->name[index];
		hl++;
		if (state->registers.a == 0x50) {
			found = 1;
			break;
		}
		state->registers.b--;
	}
	state->registers.a = 0;
	/* xor a; ld [rRAMG],a; ld [rBMODE],a on both exits. */
	state->ram_enable = 0;
	state->bank_mode = 0;
	state->registers.f = found ? (port_u8)(PORT_FLAG_Z | PORT_FLAG_C)
	                           : PORT_FLAG_Z;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
