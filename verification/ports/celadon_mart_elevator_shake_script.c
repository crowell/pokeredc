#include "port_state.h"

/* Port of CeladonMartElevatorShakeScript in scripts/CeladonMartElevator.asm.
 *
 * farjp ShakeElevator: ld b, $1e; ld hl, $7f15; jp $35d6.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define CELADON_MART_ELEVATOR_SHAKE_SCRIPT_HL 0x7f15u
#define CELADON_MART_ELEVATOR_SHAKE_SCRIPT_B 0x1eu

__attribute__((noinline, used)) void
port_celadon_mart_elevator_shake_script(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CELADON_MART_ELEVATOR_SHAKE_SCRIPT_HL >> 8);
    state->l = (port_u8)(CELADON_MART_ELEVATOR_SHAKE_SCRIPT_HL & 0xff);
    state->b = CELADON_MART_ELEVATOR_SHAKE_SCRIPT_B;
}
