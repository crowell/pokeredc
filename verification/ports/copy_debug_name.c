#include "port_state.h"

/* Port of CopyDebugName in engine/movie/title.asm.
 *
 * ld bc, $000b; jp $00b5. LD BC and JP preserve F; the tail jp is the boundary. */

#define COPY_DEBUG_NAME_BC 0x000bu

__attribute__((noinline, used)) void
port_copy_debug_name(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = (port_u8)(COPY_DEBUG_NAME_BC >> 8);
    state->c = (port_u8)(COPY_DEBUG_NAME_BC & 0xff);
}
