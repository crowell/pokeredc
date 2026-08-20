#include "port_state.h"

/* Port of RemovePokemon in home/move_mon.asm.
 *
 * jpfar _RemovePokemon: ld hl, $7b68; ld b, $01; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define REMOVE_POKEMON_HL 0x7b68u
#define REMOVE_POKEMON_B 0x01u

__attribute__((noinline, used)) void
port_remove_pokemon(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(REMOVE_POKEMON_HL >> 8);
    state->l = (port_u8)(REMOVE_POKEMON_HL & 0xff);
    state->b = REMOVE_POKEMON_B;
}
