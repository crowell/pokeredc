#include "port_state.h"

/* Port of IncrementMovePP in engine/battle/core.asm.
 *
 * After a move is used, restore one PP to that move in both the currently
 * battling pokemon's PP (battle struct) and its party counterpart. Which pair
 * of structs is used depends on hWhoseTurn (player vs enemy). */

#define IMPP_H_WHOSE_TURN 0xfff3u
#define IMPP_W_BATTLE_MON_PP 0xd02du
#define IMPP_W_PARTY_MON1_PP 0xd188u
#define IMPP_W_ENEMY_MON_PP 0xcffeu
#define IMPP_W_ENEMY_MON1_PP 0xd8c1u
#define IMPP_W_PLAYER_MOVE_LIST_INDEX 0xcc2eu
#define IMPP_W_PLAYER_MON_NUMBER 0xcc2fu
#define IMPP_W_ENEMY_MOVE_LIST_INDEX 0xcce2u
#define IMPP_W_ENEMY_MON_PARTY_POS 0xcfe8u
#define IMPP_PARTYMON_STRUCT_LENGTH 0x2cu

__attribute__((noinline, used)) void
port_increment_move_pp(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 whose = memory[IMPP_H_WHOSE_TURN];
	port_u16 battle_base;
	port_u16 party_base;
	port_u8 move_index;
	if (whose == 0) {
		battle_base = IMPP_W_BATTLE_MON_PP;
		party_base = IMPP_W_PARTY_MON1_PP;
		move_index = memory[IMPP_W_PLAYER_MOVE_LIST_INDEX];
	} else {
		battle_base = IMPP_W_ENEMY_MON_PP;
		party_base = IMPP_W_ENEMY_MON1_PP;
		move_index = memory[IMPP_W_ENEMY_MOVE_LIST_INDEX];
	}

	port_u16 offset = (port_u16)move_index;
	port_u16 battle_pp = (port_u16)(battle_base + offset);
	memory[battle_pp]++;

	port_u8 which = (whose == 0)
		? memory[IMPP_W_PLAYER_MON_NUMBER]
		: memory[IMPP_W_ENEMY_MON_PARTY_POS];
	port_u16 party_addr = (port_u16)(
		party_base + (port_u16)(IMPP_PARTYMON_STRUCT_LENGTH * which) + offset);
	memory[party_addr]++;
}
