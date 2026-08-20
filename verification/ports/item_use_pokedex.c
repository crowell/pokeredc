#include "port_state.h"

/* Port of ItemUsePokedex in engine/items/item_effects.asm.
 *
 * A jpfar/bankswitch thunk: ld a, $29; jp $3e6d
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define ItemUsePokedex_A 41u

__attribute__((noinline, used)) void
port_item_use_pokedex(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = ItemUsePokedex_A;
    /* jp to shared routine — path boundary */
}
