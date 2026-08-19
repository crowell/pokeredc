#include "port_state.h"

/*
 * CheckWarpsNoCollisionRetry2: 23 23 c3 b5 07
 *   INC HL
 *   INC HL
 *   JP 0x7b5
 *
 * Advances HL by two (the warp-check source pointer). INC HL is 16-bit and
 * affects no flags, so A/F/B/C/D/E are preserved. The JP tail is an explicit
 * boundary.
 */
__attribute__((noinline, used))
void port_check_warps_no_collision_retry2(struct cpu_register_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);
	hl = (port_u16)((hl + 2) & 0xffff);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xff);
}
