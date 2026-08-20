#include "port_state.h"

/* Port of SlotReward8Func.skip in engine/slots/slot_machine.asm.
 *
 * ld b, $02; ld de, $0008; ret. The setup preserves F; RET is the boundary. */

#define SLOT_REWARD8_FUNC_SKIP_B 0x02u
#define SLOT_REWARD8_FUNC_SKIP_DE 0x0008u

__attribute__((noinline, used)) void
port_slot_reward8_func_skip(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = SLOT_REWARD8_FUNC_SKIP_B;
    state->d = (port_u8)(SLOT_REWARD8_FUNC_SKIP_DE >> 8);
    state->e = (port_u8)(SLOT_REWARD8_FUNC_SKIP_DE & 0xff);
}
