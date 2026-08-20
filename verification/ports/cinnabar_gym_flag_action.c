#include "port_state.h"

/* Port of CinnabarGymFlagAction in scripts/CinnabarGym.asm.
 *
 * A jpfar/bankswitch thunk: ld a, $10; jp $3e6d
 * `LD HL,nn`, `LD r,imm` and `JP nn` are flag-neutral, so all other registers
 * (and F) are preserved. The tail `jp` is the path boundary. */

#define CinnabarGymFlagAction_A 16u

__attribute__((noinline, used)) void
port_cinnabar_gym_flag_action(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = CinnabarGymFlagAction_A;
    /* jp to shared routine — path boundary */
}
