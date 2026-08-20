#include "port_state.h"

/* Port of DisplayPokemartDialogue_.isThereEnoughMoney in engine/events/pokemart.asm.
 *
 * ld de, $d347; ld hl, $ff9f; ld c, $03; jp $3a8e.
 * The setup instructions preserve F; the local StringCmp JP is the boundary. */

#define DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_DE 0xd347u
#define DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_HL 0xff9fu
#define DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_C 0x03u

__attribute__((noinline, used)) void
port_display_pokemart_dialogue_is_there_enough_money(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_DE >> 8);
    state->e = (port_u8)(DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_DE & 0xff);
    state->h = (port_u8)(DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_HL >> 8);
    state->l = (port_u8)(DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_HL & 0xff);
    state->c = DISPLAY_POKEMART_DIALOGUE_IS_THERE_ENOUGH_MONEY_C;
}
