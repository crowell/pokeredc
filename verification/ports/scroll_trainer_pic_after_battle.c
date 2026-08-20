#include "port_state.h"

/* Port of ScrollTrainerPicAfterBattle in engine/battle/core.asm.
 *
 * jpfar _ScrollTrainerPicAfterBattle: ld hl, $56d3; ld b, $0e; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define SCROLL_TRAINER_PIC_AFTER_BATTLE_HL 0x56d3u
#define SCROLL_TRAINER_PIC_AFTER_BATTLE_B 0x0eu

__attribute__((noinline, used)) void
port_scroll_trainer_pic_after_battle(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(SCROLL_TRAINER_PIC_AFTER_BATTLE_HL >> 8);
    state->l = (port_u8)(SCROLL_TRAINER_PIC_AFTER_BATTLE_HL & 0xff);
    state->b = SCROLL_TRAINER_PIC_AFTER_BATTLE_B;
}
