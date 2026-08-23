#include "port_state.h"

/* Port of PrintLearnedMove in engine/pokemon/learn_move.asm:
 *
 *   ld hl, LearnedMove1Text
 *   call PrintText
 *   ld b, 1
 *   ret
 */

void port_print_text(struct cpu_register_state *, port_u8 *);

#define LEARNED_MOVE_1_TEXT_HL 0x6fadu

__attribute__((noinline, used)) void
port_print_learned_move(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(LEARNED_MOVE_1_TEXT_HL >> 8);
	state->l = (port_u8)(LEARNED_MOVE_1_TEXT_HL & 0xff);

	/* call PrintText (proven boundary) */
	port_print_text(state, memory);

	/* ld b, 1; ret */
	state->b = 0x01;
}
