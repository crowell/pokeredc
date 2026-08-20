#include "port_state.h"

/* Port of InitBattleVariables.notSafariBattle in
 * engine/battle/init_battle_variables.asm.
 *
 * ld hl, $50c6; ld b, $02; jp $35d6.
 * The setup instructions preserve F; the local bankswitch jp is the boundary. */

#define INIT_BATTLE_VARIABLES_NOT_SAFARI_BATTLE_HL 0x50c6u
#define INIT_BATTLE_VARIABLES_NOT_SAFARI_BATTLE_B 0x02u

__attribute__((noinline, used)) void
port_init_battle_variables_not_safari_battle(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(INIT_BATTLE_VARIABLES_NOT_SAFARI_BATTLE_HL >> 8);
    state->l = (port_u8)(INIT_BATTLE_VARIABLES_NOT_SAFARI_BATTLE_HL & 0xff);
    state->b = INIT_BATTLE_VARIABLES_NOT_SAFARI_BATTLE_B;
}
