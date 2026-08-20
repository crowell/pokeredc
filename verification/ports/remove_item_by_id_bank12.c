#include "port_state.h"

/* Port of RemoveItemByIDBank12 in scripts/CeladonMartRoof.asm.
 *
 * A jpfar/bankswitch thunk: ld b, $05; ld hl, $7f37; jp $35d6
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define RemoveItemByIdBank12_HL 32567u
#define RemoveItemByIdBank12_B 5u

__attribute__((noinline, used)) void
port_remove_item_by_id_bank12(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(RemoveItemByIdBank12_HL >> 8);
    state->l = (port_u8)(RemoveItemByIdBank12_HL & 0xff);
    state->b = RemoveItemByIdBank12_B;
    /* jp to shared routine — path boundary */
}
