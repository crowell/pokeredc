#include "port_state.h"

/* Port of AICureStatus in engine/battle/trainer_ai.asm.
 *
 * Clears the status of the enemy's active pokemon: zeroes the status byte in the
 * enemy team roster (indexed by wEnemyMonPartyPos), zeroes the active enemy
 * status, and clears the BADLY_POISONED bit in wEnemyBattleStatus3. */

#define AIC_W_ENEMY_MON_PARTY_POS 0xcfe8u
#define AIC_W_ENEMY_MON1_STATUS 0xd8a8u
#define AIC_W_ENEMY_MON_STATUS 0xcfe9u
#define AIC_W_ENEMY_BATTLE_STATUS3 0xd069u
#define AIC_PARTYMON_STRUCT_LENGTH 0x2cu
#define AIC_BADLY_POISONED_BIT 0u

__attribute__((noinline, used)) void
port_ai_cure_status(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 party_pos = memory[AIC_W_ENEMY_MON_PARTY_POS];
	port_u16 roster_addr = (port_u16)(
		AIC_W_ENEMY_MON1_STATUS + AIC_PARTYMON_STRUCT_LENGTH * party_pos);
	memory[roster_addr] = 0;
	memory[AIC_W_ENEMY_MON_STATUS] = 0;
	memory[AIC_W_ENEMY_BATTLE_STATUS3] &= (port_u8) ~(1u << AIC_BADLY_POISONED_BIT);
}
