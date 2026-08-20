#include "port_state.h"

struct clear_mon_pic_from_tilemap_state {
    struct cpu_register_state registers;
    port_u8 start_offset;
    port_u8 tile_writes[49];
    port_u8 clear_called;
};

#define CLEAR_TILE 0x7fu
#define CLEAR_ROWS 7
#define CLEAR_COLS 7

/* Port of ClearMonPicFromTileMap in engine/battle/animations.asm. The
 * ClearScreenArea boundary is represented by the 7x7 ordered tile writes;
 * each write is the blank tile produced by ClearScreenArea. */
__attribute__((noinline, used)) void
port_clear_mon_pic_from_tilemap(struct clear_mon_pic_from_tilemap_state *state)
{
    state->start_offset = state->registers.a;
    state->clear_called = 1;
    for (int row = 0; row < CLEAR_ROWS; row++)
        for (int col = 0; col < CLEAR_COLS; col++)
            state->tile_writes[row * CLEAR_COLS + col] = CLEAR_TILE;
}
