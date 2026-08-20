#include "port_state.h"

/* Port of CinnabarGymGateFlagAction in engine/events/hidden_events/cinnabar_gym_quiz.asm.
 *
 *   ld hl, $d79c ; ld a, $10 ; jp $3e6d
 *
 * A flag-action thunk: loads HL with the flag structure and A with the action
 * id, then jumps to the shared flag-action routine. `LD HL,nn`, `LD A,imm` and
 * `JP nn` are all flag-neutral, so B, C, D, E and F are preserved. The tail
 * `jp` is the path boundary. */

#define CGG_HL 0xd79cu
#define CGG_A  0x10u

__attribute__((noinline, used)) void
port_cinnabar_gym_gate_flag_action(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CGG_HL >> 8);
    state->l = (port_u8)(CGG_HL & 0xff);
    state->a = CGG_A;
    /* jp $3e6d — path boundary */
}
