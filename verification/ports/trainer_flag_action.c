#include "port_state.h"

/* Port of TrainerFlagAction in home/trainers.asm.
 *
 * predef_jump FlagActionPredef: ld a, $10; jp $3e6d.
 * LD A and JP preserve F; the tail jp is the path boundary. */

#define TRAINER_FLAG_ACTION_A 0x10u

__attribute__((noinline, used)) void
port_trainer_flag_action(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = TRAINER_FLAG_ACTION_A;
}
