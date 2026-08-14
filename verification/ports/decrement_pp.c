#include "port_state.h"

/* Port of DecrementPP in engine/battle/decrement_pp.asm.
 *
 * After a move is used, decrement the PP of that move in the battle struct and
 * (unless the pokemon is transformed) in the party struct. Several early exits
 * skip the decrement entirely: when the move is Struggle, or when battle-status
 * flags indicate the PP should not be spent (storing energy / thrashing / multi-
 * hit, or using Rage), or when the pokemon is transformed. */

#define DPP_W_PLAYER_BATTLE_STATUS1 0xd062u
#define DPP_W_PLAYER_BATTLE_STATUS2 0xd063u
#define DPP_W_PLAYER_BATTLE_STATUS3 0xd064u
#define DPP_W_BATTLE_MON_PP 0xd02du
#define DPP_W_PARTY_MON1_PP 0xd188u
#define DPP_W_PLAYER_MON_NUMBER 0xcc2fu
#define DPP_W_PLAYER_MOVE_LIST_INDEX 0xcc2eu
#define DPP_PARTYMON_STRUCT_LENGTH 0x2cu
#define DPP_STRUGGLE 0xa5u
#define DPP_STATUS1_MASK 0x07u /* STORING_ENERGY | THRASHING_ABOUT | ATTACKING_MULTIPLE_TIMES */
#define DPP_USING_RAGE 0x40u   /* bit 6 of wPlayerBattleStatus2 */
#define DPP_TRANSFORMED 0x08u  /* bit 3 of wPlayerBattleStatus3 */

__attribute__((noinline, used)) void
port_decrement_pp(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 de = (port_u16)((state->d << 8) | state->e);
	port_u8 move = memory[de];
	if (move == DPP_STRUGGLE)
		return;
	port_u8 status1 = memory[DPP_W_PLAYER_BATTLE_STATUS1];
	if (status1 & DPP_STATUS1_MASK)
		return;
	port_u8 status2 = memory[DPP_W_PLAYER_BATTLE_STATUS2];
	if (status2 & DPP_USING_RAGE)
		return;

	/* Decrement the battle move's PP. */
	port_u8 move_index = memory[DPP_W_PLAYER_MOVE_LIST_INDEX];
	port_u16 battle_pp = (port_u16)(DPP_W_BATTLE_MON_PP + move_index);
	memory[battle_pp]--;

	port_u8 status3 = memory[DPP_W_PLAYER_BATTLE_STATUS3];
	if (status3 & DPP_TRANSFORMED)
		return;

	/* Decrement the corresponding party move's PP. */
	port_u8 which = memory[DPP_W_PLAYER_MON_NUMBER];
	port_u16 party_pp = (port_u16)(
		DPP_W_PARTY_MON1_PP +
		(port_u16)(DPP_PARTYMON_STRUCT_LENGTH * which) + move_index);
	memory[party_pp]--;
}
