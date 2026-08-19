#include "port_state.h"

/* Port of LoadBattleTransitionTile in engine/battle/transition.asm.
 *
 * Sets up the source/destination/length triple for the shared tilemap copy
 * routine and tail-calls it. The RGBDS original is:
 *
 *   ld hl, wTilemap ; ld de, CopyDataDest ; ld bc, 8 ; jp CopyTilemap
 *
 * Here the three 16-bit immediates are bound to the constants below and the
 * tail `jp` is the path boundary. A and F are preserved. */

#define LBTT_SRC  0x8ff0u
#define LBTT_DEST 0x4a59u
#define LBTT_LEN  0x1c01u

__attribute__((noinline, used)) void
port_load_battle_transition_tile(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(LBTT_SRC >> 8);
    state->l = (port_u8)(LBTT_SRC & 0xff);
    state->d = (port_u8)(LBTT_DEST >> 8);
    state->e = (port_u8)(LBTT_DEST & 0xff);
    state->b = (port_u8)(LBTT_LEN >> 8);
    state->c = (port_u8)(LBTT_LEN & 0xff);
    /* jp 0x1848 (shared CopyTilemap routine) — path boundary */
}
