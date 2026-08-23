#include "port_state.h"

/* Port of BlackbeltAI in engine/battle/trainer_ai.asm:
 *
 *   cp 13 percent - 1     ; $ff*13/100 - 1 = $20
 *   ret nc                ; keep current move unless A < threshold
 *   jp AIUseXAttack       ; A := X_ATTACK item, B := effect param
 */

void port_ai_use_x_attack(struct cpu_register_state *);

#define AI_THRESHOLD 0x20u

__attribute__((noinline, used)) void
port_blackbelt_ai(struct cpu_register_state *state)
{
	port_u8 a = state->a;
	port_u8 f = PORT_FLAG_N;

	/* cp $20: Z = (a == $20), N set, H clear (low nibble of $20 is 0),
	 * C = (a < $20). */
	if (a == AI_THRESHOLD)
		f |= PORT_FLAG_Z;
	if (a < AI_THRESHOLD)
		f |= PORT_FLAG_C;
	state->f = f;

	if (!(state->f & PORT_FLAG_C))
		return; /* ret nc */

	port_ai_use_x_attack(state); /* tail call */
}
