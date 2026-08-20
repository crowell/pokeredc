#include "port_state.h"

/* Port of IsMoveHM in home/names.asm.
 *
 * ld hl, $3052; ld de, $0001; jp $3dab.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define IS_MOVE_HM_HL 0x3052u
#define IS_MOVE_HM_DE 0x0001u

__attribute__((noinline, used)) void
port_is_move_hm(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(IS_MOVE_HM_HL >> 8);
    state->l = (port_u8)(IS_MOVE_HM_HL & 0xff);
    state->d = (port_u8)(IS_MOVE_HM_DE >> 8);
    state->e = (port_u8)(IS_MOVE_HM_DE & 0xff);
}
