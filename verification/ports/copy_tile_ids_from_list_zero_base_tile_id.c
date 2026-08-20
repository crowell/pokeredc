#include "port_state.h"

/* Port of CopyTileIDsFromList_ZeroBaseTileID in engine/movie/intro.asm.
 *
 * A jpfar/bankswitch thunk: ld c, $00; ld a, $31; jp $3e6d
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define CopyTileIdsFromListZeroBaseTileId_A 49u
#define CopyTileIdsFromListZeroBaseTileId_C 0u

__attribute__((noinline, used)) void
port_copy_tile_ids_from_list_zero_base_tile_id(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = CopyTileIdsFromListZeroBaseTileId_A;
    state->c = CopyTileIdsFromListZeroBaseTileId_C;
    /* jp to shared routine — path boundary */
}
