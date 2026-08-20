#include "port_state.h"

struct sprite_position_bankswitch_state {
    struct cpu_register_state registers;
    port_u8 rom_bank;
};

#define BANK_TRAINER_SIGHT 21u

/* Port of SpritePositionBankswitch in home/trainers.asm.
 *
 * ld b, BANK("Trainer Sight"); jp Bankswitch. The bank register is an
 * explicit state field; the JP HL/Bankswitch tail is the path boundary. */

__attribute__((noinline, used)) void
port_sprite_position_bankswitch(struct sprite_position_bankswitch_state *state)
{
    state->registers.b = BANK_TRAINER_SIGHT;
    state->rom_bank = BANK_TRAINER_SIGHT;
}
