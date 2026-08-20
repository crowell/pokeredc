#include "port_state.h"

/* Port of TrainerWalkUpToPlayer_Bank0 in home/trainers.asm.
 *
 * farjp TrainerWalkUpToPlayer: ld b, $15; ld hl, $6881; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define TRAINER_WALK_UP_TO_PLAYER_BANK0_HL 0x6881u
#define TRAINER_WALK_UP_TO_PLAYER_BANK0_B 0x15u

__attribute__((noinline, used)) void
port_trainer_walk_up_to_player_bank0(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(TRAINER_WALK_UP_TO_PLAYER_BANK0_HL >> 8);
    state->l = (port_u8)(TRAINER_WALK_UP_TO_PLAYER_BANK0_HL & 0xff);
    state->b = TRAINER_WALK_UP_TO_PLAYER_BANK0_B;
}
