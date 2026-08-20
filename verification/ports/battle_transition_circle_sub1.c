#include "port_state.h"

/* Port of BattleTransition_Circle_Sub1 through the first
 * BattleTransition_Circle_Sub2 call. */
__attribute__((noinline, used)) void
port_battle_transition_circle_sub1(struct cpu_register_state *registers)
{
	registers->a = registers->b;
}
