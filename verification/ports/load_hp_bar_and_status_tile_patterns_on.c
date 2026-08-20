#include "port_state.h"

/* Port of LoadHpBarAndStatusTilePatterns.on in home/load_font.asm.
 *
 * ld de, $5ea0; ld hl, $9620; ld bc, $041e; jp $1848.
 * The setup instructions preserve F; the local transfer jp is the boundary. */

#define LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_DE 0x5ea0u
#define LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_HL 0x9620u
#define LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_BC 0x041eu

__attribute__((noinline, used)) void
port_load_hp_bar_and_status_tile_patterns_on(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_DE >> 8);
    state->e = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_DE & 0xff);
    state->h = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_HL >> 8);
    state->l = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_HL & 0xff);
    state->b = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_BC >> 8);
    state->c = (port_u8)(LOAD_HP_BAR_AND_STATUS_TILE_PATTERNS_ON_BC & 0xff);
}
