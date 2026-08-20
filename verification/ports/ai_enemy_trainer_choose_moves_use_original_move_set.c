#include "port_state.h"

/* Port of AIEnemyTrainerChooseMoves.useOriginalMoveSet in
 * engine/battle/trainer_ai.asm.
 *
 * ld hl, $cfed; ret. LD HL preserves F; the local RET is the boundary. */

#define AI_ENEMY_TRAINER_CHOOSE_MOVES_USE_ORIGINAL_MOVE_SET_HL 0xcfedu

__attribute__((noinline, used)) void
port_ai_enemy_trainer_choose_moves_use_original_move_set(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(AI_ENEMY_TRAINER_CHOOSE_MOVES_USE_ORIGINAL_MOVE_SET_HL >> 8);
    state->l = (port_u8)(AI_ENEMY_TRAINER_CHOOSE_MOVES_USE_ORIGINAL_MOVE_SET_HL & 0xff);
}
