#include "port_state.h"

/* Port of TrainerInfo_FarCopyData in engine/menus/start_sub_menus.asm:
 *
 *   ld a, BANK(TrainerInfoTextBoxTileGraphics)   ; $0b
 *   jp FarCopyData2
 *
 * FarCopyData2's proven contract: A carries the source bank, the current
 * hLoadedROMBank / rROMB values are saved, CopyData transfers BC bytes from
 * the banked source to DE, then the bank and AF are restored.
 */

void port_far_copy_data2(struct far_copy_data2_state *, port_u8 *);

#define W_TRAINER_INFO_GFX_BANK 0x0bu
#define H_LOADED_ROM_BANK       0xffb8u
#define R_ROMB                  0x2000u

__attribute__((noinline, used)) void
port_trainer_info_far_copy_data(struct cpu_register_state *state,
				port_u8 *memory)
{
	struct far_copy_data2_state fc;

	fc.registers = *state;
	fc.registers.a = W_TRAINER_INFO_GFX_BANK;
	fc.loaded_bank = memory[H_LOADED_ROM_BANK];
	fc.rom_bank = memory[R_ROMB];

	port_far_copy_data2(&fc, memory);

	*state = fc.registers;
	memory[H_LOADED_ROM_BANK] = fc.loaded_bank;
	memory[R_ROMB] = fc.rom_bank;
}
