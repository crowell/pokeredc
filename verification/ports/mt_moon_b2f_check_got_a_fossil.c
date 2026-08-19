#include "port_state.h"

/* Port of MtMoonB2FCheckGotAFossil in scripts/MtMoonB2F.asm.
 *
 * The RGBDS original reads the combined fossil-event flag byte, masks the two
 * fossil bits, and jumps to CheckFightingMapTrainers when both are clear
 * (zero); otherwise it returns. The jump is modelled as the path boundary.
 *
 *   ld a, [wEventFlags + X] ; and $c0 ; jp z, CheckFightingMapTrainers ; ret */

#define MMB2F_ADDR 0xd7f6u
#define MMB2F_MASK 0xc0u

__attribute__((noinline, used)) void
port_mt_moon_b2f_check_got_a_fossil(struct cpu_register_state *state, port_u8 *memory)
{
    state->a = (port_u8)(memory[MMB2F_ADDR] & MMB2F_MASK);
    /* jp z, CheckFightingMapTrainers (boundary) ; ret (boundary) */
}
