#include "port_state.h"

/* Port of BrunoAI in engine/battle/trainer_ai.asm:
 *
 *   cp 25 percent + 1     ; $40
 *   ret nc
 *   jp AIUseXDefend
 */

void port_ai_use_x_defend(struct cpu_register_state *);

#define AI_THRESHOLD 0x40u

__attribute__((noinline, used)) void
port_bruno_ai(struct cpu_register_state *state)
{
	port_u8 a = state->a;
	port_u8 f = PORT_FLAG_N;

	/* cp $40: Z = (a == $40), N set, H clear (low nibble of $40 is 0),
	 * C = (a < $40). */
	if (a == AI_THRESHOLD)
		f |= PORT_FLAG_Z;
	if (a < AI_THRESHOLD)
		f |= PORT_FLAG_C;
	state->f = f;

	if (!(state->f & PORT_FLAG_C))
		return; /* ret nc */

	port_ai_use_x_defend(state); /* tail call */
}
