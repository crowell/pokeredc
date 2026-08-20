#include "port_state.h"

/* Port of FillFourRowsWithBlack in engine/movie/credits.asm.
 *
 * ld bc, $0050; ld a, $7e; jp $36e0.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define FILL_FOUR_ROWS_WITH_BLACK_BC 0x0050u
#define FILL_FOUR_ROWS_WITH_BLACK_A 0x7eu

__attribute__((noinline, used)) void
port_fill_four_rows_with_black(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = (port_u8)(FILL_FOUR_ROWS_WITH_BLACK_BC >> 8);
    state->c = (port_u8)(FILL_FOUR_ROWS_WITH_BLACK_BC & 0xff);
    state->a = FILL_FOUR_ROWS_WITH_BLACK_A;
}
