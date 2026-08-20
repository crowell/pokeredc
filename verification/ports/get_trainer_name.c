#include "port_state.h"

/* Port of GetTrainerName in home/trainers2.asm.
 *
 * farjp GetTrainerName_: ld b, $04; ld hl, $7a58; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define GET_TRAINER_NAME_HL 0x7a58u
#define GET_TRAINER_NAME_B 0x04u

__attribute__((noinline, used)) void
port_get_trainer_name(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(GET_TRAINER_NAME_HL >> 8);
    state->l = (port_u8)(GET_TRAINER_NAME_HL & 0xff);
    state->b = GET_TRAINER_NAME_B;
}
