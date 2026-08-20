#include "port_state.h"

/* Port of EndNPCMovementScript in home/npc_movement.asm.
 *
 * farjp _EndNPCMovementScript: ld b, $06; ld hl, $641d; jp $35d6.
 * This outer wrapper is distinct from the existing inner implementation port;
 * the setup instructions preserve F and the tail jp is the path boundary. */

#define END_NPC_MOVEMENT_SCRIPT_THUNK_HL 0x641du
#define END_NPC_MOVEMENT_SCRIPT_THUNK_B 0x06u

__attribute__((noinline, used)) void
port_end_npc_movement_script_thunk(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(END_NPC_MOVEMENT_SCRIPT_THUNK_HL >> 8);
    state->l = (port_u8)(END_NPC_MOVEMENT_SCRIPT_THUNK_HL & 0xff);
    state->b = END_NPC_MOVEMENT_SCRIPT_THUNK_B;
}
