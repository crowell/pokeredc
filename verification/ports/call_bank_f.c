#include "port_state.h"

/* Port of CallBankF in engine/battle/move_effects/conversion.asm.
 *
 *   ld b, $0f ; jp $36d6
 *
 * Loads B with the target bank and jumps to the far-call/bankswitch routine.
 * `LD B,imm` and `JP nn` are both flag-neutral, so A, C, D, E, F, H and L are
 * preserved (only B changes). The tail `jp` is the path boundary. */

#define CALL_BANK_F_B 0x0fu

__attribute__((noinline, used)) void
port_call_bank_f(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = CALL_BANK_F_B;
    /* jp $36d6 (bankswitch routine) — path boundary */
}
