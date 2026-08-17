#include "port_state.h"

#define BANK_TRAINER_SIGHT 21u
#define R_ROMB 0xFF00u

/* Port of SpritePositionBankswitch (home/trainers.asm): ld b, BANK("Trainer Sight"); jp Bankswitch.
 *
 * Switches the ROM bank to the Trainer Sight bank and indirect-jumps (via
 * Bankswitch) to the routine whose address is in HL. The jp hl target is an
 * explicit boundary; only the bank switch is modeled observably (matching the
 * framework's R_ROMB alias used by port_copy_video_data). */
__attribute__((noinline, used)) void
port_sprite_position_bankswitch(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = BANK_TRAINER_SIGHT;
	memory[R_ROMB] = state->b;
}
