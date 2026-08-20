#include "port_state.h"

/* Port of GetTrainerName_.foundName in engine/battle/get_trainer_name.asm.
 *
 * ld de, $d04a; ld bc, $000d; jp $00b5.
 * The setup instructions preserve F; the local branch's jp is the boundary. */

#define GET_TRAINER_NAME_FOUND_NAME_DE 0xd04au
#define GET_TRAINER_NAME_FOUND_NAME_BC 0x000du

__attribute__((noinline, used)) void
port_get_trainer_name_found_name(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(GET_TRAINER_NAME_FOUND_NAME_DE >> 8);
    state->e = (port_u8)(GET_TRAINER_NAME_FOUND_NAME_DE & 0xff);
    state->b = (port_u8)(GET_TRAINER_NAME_FOUND_NAME_BC >> 8);
    state->c = (port_u8)(GET_TRAINER_NAME_FOUND_NAME_BC & 0xff);
}
