#include "port_state.h"

/* Port of StatusScreen_ClearName in engine/pokemon/status_screen.asm.
 *
 * ld bc, $000a; ld a, $7f; jp $36e0.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define STATUS_SCREEN_CLEAR_NAME_BC 0x000au
#define STATUS_SCREEN_CLEAR_NAME_A 0x7fu

__attribute__((noinline, used)) void
port_status_screen_clear_name(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = (port_u8)(STATUS_SCREEN_CLEAR_NAME_BC >> 8);
    state->c = (port_u8)(STATUS_SCREEN_CLEAR_NAME_BC & 0xff);
    state->a = STATUS_SCREEN_CLEAR_NAME_A;
}
