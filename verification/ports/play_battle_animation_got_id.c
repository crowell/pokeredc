#include "port_state.h"

/* Port of PlayBattleAnimationGotID (engine/battle/effects.asm).
 *
 * Preserves HL/DE/BC and runs the MoveAnimation predef for the animation ID in
 * wAnimationID. MoveAnimation is not ported, so its (sprite/animation) effects
 * are an explicit boundary; the function itself only preserves registers,
 * which the C model already does. Thus it has no observable memory/flag effect
 * beyond the register preservation that the C calling convention supplies. */
__attribute__((noinline, used)) void
port_play_battle_animation_got_id(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	(void)memory;
}
