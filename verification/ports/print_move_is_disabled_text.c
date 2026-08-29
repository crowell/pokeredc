#include "port_state.h"

struct print_move_disabled_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

#define W_PLAYER_SELECTED_MOVE 0xccdcu
#define W_PLAYER_BATTLE_STATUS1 0xd062u
#define W_ENEMY_BATTLE_STATUS1 0xd067u
#define W_NAMED_OBJECT_INDEX 0xd11eu
#define W_NAME_BUFFER 0xcd6du
#define MOVE_IS_DISABLED_TEXT 0x5aa8u
#define CHARGING_UP_MASK (1u << 4)

/* Port of PrintMoveIsDisabledText through the GetMoveName/PrintText setup
 * boundaries.  GetMoveName and PrintText are independently proven callees;
 * this entry preserves their observable pointer and memory effects. */
__attribute__((noinline, used)) void
port_print_move_is_disabled_text(struct print_move_disabled_state *state,
	port_u8 *memory)
{
	if (state->whose_turn == 0u) {
		state->registers.h = (port_u8)(W_PLAYER_SELECTED_MOVE >> 8);
		state->registers.l = (port_u8)W_PLAYER_SELECTED_MOVE;
		state->registers.d = (port_u8)(W_PLAYER_BATTLE_STATUS1 >> 8);
		state->registers.e = (port_u8)W_PLAYER_BATTLE_STATUS1;
		state->registers.f |= PORT_FLAG_Z;
		memory[W_PLAYER_BATTLE_STATUS1] &= (port_u8)~CHARGING_UP_MASK;
		memory[W_NAMED_OBJECT_INDEX] = memory[W_PLAYER_SELECTED_MOVE];
	} else {
		state->registers.h = (port_u8)((W_PLAYER_SELECTED_MOVE + 1u) >> 8);
		state->registers.l = (port_u8)(W_PLAYER_SELECTED_MOVE + 1u);
		state->registers.d = (port_u8)(W_ENEMY_BATTLE_STATUS1 >> 8);
		state->registers.e = (port_u8)W_ENEMY_BATTLE_STATUS1;
		memory[W_ENEMY_BATTLE_STATUS1] &= (port_u8)~CHARGING_UP_MASK;
		memory[W_NAMED_OBJECT_INDEX] = memory[W_PLAYER_SELECTED_MOVE + 1u];
	}
	state->registers.a = state->whose_turn;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		(state->registers.a == 0u ? PORT_FLAG_Z : 0u));

	/* GetMoveName restores HL and returns DE=wNameBuffer. */
	state->registers.d = (port_u8)(W_NAME_BUFFER >> 8);
	state->registers.e = (port_u8)W_NAME_BUFFER;
	state->registers.h = (port_u8)(MOVE_IS_DISABLED_TEXT >> 8);
	state->registers.l = (port_u8)MOVE_IS_DISABLED_TEXT;
}
