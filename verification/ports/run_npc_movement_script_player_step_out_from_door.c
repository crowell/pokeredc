#include "port_state.h"

/* Port of RunNPCMovementScript.playerStepOutFromDoor in home/npc_movement.asm.
 *
 * farjp PlayerStepOutFromDoor: ld b, $06; ld hl, $63e0; jp $35d6.
 * The setup instructions preserve F; the local bankswitch jp is the boundary. */

#define RUN_NPC_MOVEMENT_SCRIPT_PLAYER_STEP_OUT_FROM_DOOR_HL 0x63e0u
#define RUN_NPC_MOVEMENT_SCRIPT_PLAYER_STEP_OUT_FROM_DOOR_B 0x06u

__attribute__((noinline, used)) void
port_run_npc_movement_script_player_step_out_from_door(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(RUN_NPC_MOVEMENT_SCRIPT_PLAYER_STEP_OUT_FROM_DOOR_HL >> 8);
    state->l = (port_u8)(RUN_NPC_MOVEMENT_SCRIPT_PLAYER_STEP_OUT_FROM_DOOR_HL & 0xff);
    state->b = RUN_NPC_MOVEMENT_SCRIPT_PLAYER_STEP_OUT_FROM_DOOR_B;
}
