#include "port_state.h"

/* Port of LoadFossilItemAndMonNameBank1D in scripts/CinnabarLabFossilRoom.asm.
 *
 * farjp LoadFossilItemAndMonName: ld b, $18; ld hl, $50eb; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define LOAD_FOSSIL_ITEM_AND_MON_NAME_BANK1D_HL 0x50ebu
#define LOAD_FOSSIL_ITEM_AND_MON_NAME_BANK1D_B 0x18u

__attribute__((noinline, used)) void
port_load_fossil_item_and_mon_name_bank1d(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(LOAD_FOSSIL_ITEM_AND_MON_NAME_BANK1D_HL >> 8);
    state->l = (port_u8)(LOAD_FOSSIL_ITEM_AND_MON_NAME_BANK1D_HL & 0xff);
    state->b = LOAD_FOSSIL_ITEM_AND_MON_NAME_BANK1D_B;
}
