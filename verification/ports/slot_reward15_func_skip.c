#include "port_state.h"

/* Port of SlotReward15Func.skip in engine/slots/slot_machine.asm.
 *
 * ld b, $04; ld de, $000f; ret. The setup preserves F; RET is the boundary. */

#define SLOT_REWARD15_FUNC_SKIP_B 0x04u
#define SLOT_REWARD15_FUNC_SKIP_DE 0x000fu

__attribute__((noinline, used)) void
port_slot_reward15_func_skip(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = SLOT_REWARD15_FUNC_SKIP_B;
    state->d = (port_u8)(SLOT_REWARD15_FUNC_SKIP_DE >> 8);
    state->e = (port_u8)(SLOT_REWARD15_FUNC_SKIP_DE & 0xff);
}
