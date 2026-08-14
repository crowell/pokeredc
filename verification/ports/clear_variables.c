#include "port_state.h"

/* Port of ClearVariablesOnEnterMap in engine/overworld/clear_variables.asm.
 *
 * It writes the constant screen height to the WY registers, zeroes a set of
 * status / joy / flag bytes (including the two-byte wCardKeyDoorY), and then
 * delegates to FillMemory to clear the [wWhichTrade, wStandingOnWarpPadOrHole)
 * range. */
void port_fill_memory(struct fill_memory_state *state, port_u8 *memory);

#define SCREEN_HEIGHT_PX 0x90
#define H_WY 0xffb0
#define R_WY 0xff4a
#define H_AUTO_BG_TRANSFER_ENABLED 0xffba
#define H_JOY_PRESSED 0xffb3
#define H_JOY_RELEASED 0xffb2
#define H_JOY_HELD 0xffb4
#define W_STEP_COUNTER 0xd13b
#define W_LONE_ATTACK_NO 0xd05c
#define W_ACTION_RESULT_OR_TOOK_BATTLE_TURN 0xcd6a
#define W_UNUSED_MAP_VARIABLE 0xd5a3
#define W_CARD_KEY_DOOR_Y 0xd73f
#define W_WHICH_TRADE 0xcd3d
#define W_STANDING_ON_WARP_PAD_OR_HOLE 0xcd5b

__attribute__((noinline, used)) void
port_clear_variables_on_enter_map(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->a = SCREEN_HEIGHT_PX;
	memory[H_WY] = state->a;
	memory[R_WY] = state->a;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;
	memory[W_STEP_COUNTER] = 0;
	memory[W_LONE_ATTACK_NO] = 0;
	memory[H_JOY_PRESSED] = 0;
	memory[H_JOY_RELEASED] = 0;
	memory[H_JOY_HELD] = 0;
	memory[W_ACTION_RESULT_OR_TOOK_BATTLE_TURN] = 0;
	memory[W_UNUSED_MAP_VARIABLE] = 0;
	memory[W_CARD_KEY_DOOR_Y] = 0;
	memory[W_CARD_KEY_DOOR_Y + 1] = 0;

	/* FillMemory [wWhichTrade, wStandingOnWarpPadOrHole) with 0. */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	state->h = (port_u8)(W_WHICH_TRADE >> 8);
	state->l = (port_u8)W_WHICH_TRADE;
	state->b = 0;
	state->c = (port_u8)(W_STANDING_ON_WARP_PAD_OR_HOLE - W_WHICH_TRADE);
	{
		struct fill_memory_state fms;
		fms.registers = *state;
		port_fill_memory(&fms, memory);
		*state = fms.registers;
	}
}
