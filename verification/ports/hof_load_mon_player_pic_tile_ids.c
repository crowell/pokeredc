#include "port_state.h"

/* Port of HoFLoadMonPlayerPicTileIDs in engine/movie/hall_of_fame.asm.
 *
 * ld b, $00; ld hl, $c410; ld a, $31; jp $3e6d.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define HOF_LOAD_MON_PLAYER_PIC_TILE_IDS_HL 0xc410u
#define HOF_LOAD_MON_PLAYER_PIC_TILE_IDS_A 0x31u

__attribute__((noinline, used)) void
port_hof_load_mon_player_pic_tile_ids(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = 0;
    state->h = (port_u8)(HOF_LOAD_MON_PLAYER_PIC_TILE_IDS_HL >> 8);
    state->l = (port_u8)(HOF_LOAD_MON_PLAYER_PIC_TILE_IDS_HL & 0xff);
    state->a = HOF_LOAD_MON_PLAYER_PIC_TILE_IDS_A;
}
