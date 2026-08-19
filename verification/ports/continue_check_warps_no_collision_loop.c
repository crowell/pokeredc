#include "port_state.h"

/*
 * ContinueCheckWarpsNoCollisionLoop: 04 0d c2 cc 06
 *   INC B
 *   DEC C
 *   JP NZ, 0x6cc
 *
 * Advances the collision-check counters. INC B and DEC C do not affect the
 * carry flag, and DEC C overwrites the flags set by INC B, so the final
 * flags come from DEC C: Z=(C==0), N=1, H set when the low nibble of C was
 * non-zero (no borrow from bit 4), C preserved from the input. The JP NZ
 * tail is an explicit boundary.
 *
 * NOTE: the data path (B+1, C-1, other registers preserved) is proven by the
 * angr path-equivalence test. The F byte is computed here per SM83 semantics
 * but is excluded from that proof because angr's pcode Z80 backend composes
 * the flag register incorrectly for 8-bit INC/DEC.
 */
__attribute__((noinline, used))
void port_continue_check_warps_no_collision_loop(struct cpu_register_state *state)
{
	port_u8 cflag = (port_u8)(state->f & 0x10);
	port_u8 b = (port_u8)(state->b + 1);
	port_u8 c = (port_u8)(state->c - 1);
	port_u8 z = (c == 0) ? 0x80 : 0;
	port_u8 h = ((state->c & 0x0f) != 0) ? 0x20 : 0;
	state->b = b;
	state->c = c;
	state->f = (port_u8)(z | 0x40 | h | cflag);
}
