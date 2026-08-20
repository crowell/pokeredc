#include "port_state.h"

/* Port of GetDefaultName.foundName in engine/movie/oak_speech/oak_speech2.asm.
 *
 * ld h, d; ld l, e; ld de, $cd6d; ld bc, $0014; jp $00b5.
 * All setup instructions preserve F; the local CopyData JP is the boundary. */

#define GET_DEFAULT_NAME_FOUND_NAME_DE 0xcd6du
#define GET_DEFAULT_NAME_FOUND_NAME_BC 0x0014u

__attribute__((noinline, used)) void
port_get_default_name_found_name(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = state->d;
    state->l = state->e;
    state->d = (port_u8)(GET_DEFAULT_NAME_FOUND_NAME_DE >> 8);
    state->e = (port_u8)(GET_DEFAULT_NAME_FOUND_NAME_DE & 0xff);
    state->b = (port_u8)(GET_DEFAULT_NAME_FOUND_NAME_BC >> 8);
    state->c = (port_u8)(GET_DEFAULT_NAME_FOUND_NAME_BC & 0xff);
}
