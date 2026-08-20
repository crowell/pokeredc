#include "port_state.h"

struct determine_wild_opponent_state {
    struct cpu_register_state registers;
    port_u8 status_flags6;
    port_u8 joy_held;
    port_u8 no_random_battle_steps_left;
    port_u8 encounter_found;
    port_u8 init_battle_common_called;
};

#define BIT_DEBUG_MODE 1u
#define B_PAD_B 1u

/* Port of DetermineWildOpponent in engine/battle/core.asm. The
 * TryDoWildEncounter and InitBattleCommon boundaries are explicit state. */
__attribute__((noinline, used)) void
port_determine_wild_opponent(struct determine_wild_opponent_state *state)
{
    if ((state->status_flags6 & (1u << BIT_DEBUG_MODE)) != 0 &&
        (state->joy_held & (1u << B_PAD_B)) != 0)
        return;
    if (state->no_random_battle_steps_left != 0)
        return;
    state->encounter_found = 1;
    state->init_battle_common_called = 1;
}
