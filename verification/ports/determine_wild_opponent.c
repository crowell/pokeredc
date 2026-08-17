#include "port_state.h"

#define W_STATUS_FLAGS6 0xd732u
#define H_JOY_HELD 0xffb4u
#define W_NUM_NO_RANDOM_BATTLE_STEPS_LEFT 0xd13cu
#define BIT_DEBUG_MODE 1u
#define B_PAD_B 1u

/* Port of DetermineWildOpponent (engine/battle/core.asm).
 *
 * Decides whether a wild battle should begin. It gates off wild encounters
 * when (a) the debug-mode flag is set and the B button is held, or (b) the
 * player still has no-random-battle steps remaining. If neither gate trips it
 * runs TryDoWildEncounter (callfar) to pick an opponent; on success it falls
 * through into InitBattleCommon.
 *
 * The callfar TryDoWildEncounter and the InitBattleCommon tail are explicit
 * boundaries. TryDoWildEncounter is modeled as always proceeding to the
 * fall-through (an encounter is found), so the port performs the gate checks
 * and then delegates to port_init_battle_common. */
extern void port_init_battle_common(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_determine_wild_opponent(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 status = memory[W_STATUS_FLAGS6];
	if (status & (1u << BIT_DEBUG_MODE)) {
		port_u8 joy = memory[H_JOY_HELD];
		if (joy & (1u << B_PAD_B))
			return;
	}
	if (memory[W_NUM_NO_RANDOM_BATTLE_STEPS_LEFT] != 0)
		return;
	/* fall through to InitBattleCommon (TryDoWildEncounter boundary modeled
	 * as a found encounter) */
	port_init_battle_common(state, memory);
}
