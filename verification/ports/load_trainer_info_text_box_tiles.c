#include "port_state.h"

/* Port of LoadTrainerInfoTextBoxTiles in engine/link/cable_club.asm.
 *
 *   ld de, $7b98 ; ld hl, $9760 ; lb bc, $0b, $09 ; jp $1848
 *
 * `lb bc, BANK, count` packs to `ld bc, $0b09` (B = bank, C = tile count).
 * Every instruction is flag-neutral (LD rr,nn and JP nn), so A and F are
 * preserved; only DE, HL and BC change. The tail `jp` is the path boundary. */

#define LTIT_DE 0x7b98u
#define LTIT_B  0x0bu
#define LTIT_C  0x09u

__attribute__((noinline, used)) void
port_load_trainer_info_text_box_tiles(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(LTIT_DE >> 8);
    state->e = (port_u8)(LTIT_DE & 0xff);
    state->h = (port_u8)(0x9760u >> 8);
    state->l = (port_u8)(0x9760u & 0xff);
    state->b = LTIT_B;
    state->c = LTIT_C;
    /* jp $1848 (CopyVideoData) — path boundary */
}
