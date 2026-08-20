#include "port_state.h"

/* Port of Evolution_FlagAction in engine/pokemon/evos_moves.asm.
 *
 *   ld a, $10 ; jp $3e6d
 *
 * `LD A,imm` does not affect flags, and `JP nn` is flag-neutral, so B, C, D,
 * E, F, H and L are all preserved (only A changes). The tail `jp` is the path
 * boundary. */

#define FLAG_ACTION_A 0x10u

__attribute__((noinline, used)) void
port_evolution_flag_action(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->a = FLAG_ACTION_A;
    /* jp $3e6d — path boundary */
}
