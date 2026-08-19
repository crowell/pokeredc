#include "port_state.h"

/*
 * GetwMoves: 21 dcd0 4f 06 00 09 7e c9
 *   LD HL, 0xd0dc
 *   LD C, A
 *   LD B, 0
 *   ADD HL, BC
 *   LD A, (HL)
 *   RET
 *
 * Indexes the wMoves-equivalent table at 0xd0dc by the move id in A and
 * returns the byte there. ADD HL, BC never carries for a valid move id
 * (0xd0dc + A <= 0xd1db), so N/H/C stay 0 and Z is preserved from input.
 */
__attribute__((noinline, used))
void port_get_w_moves(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)0xd0dc + (port_u16)state->a;

	state->b = 0;
	state->c = state->a;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
	state->a = memory[hl];
	/* ADD HL, BC clears N/H/C and preserves Z; low 4 F bits are always 0. */
	state->f = (port_u8)(state->f & 0x80);
}
