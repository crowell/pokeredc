#include "port_state.h"

/*
 * PrintBCDDigit: e6 0f a7 28 15
 *   AND 0xf
 *   AND A
 *   JR Z, 0x161e
 *
 * Masks the low nibble of A. The second `AND A` overwrites the flags, so
 * the final state is A = A_in & 0xf with Z=(A==0), N=0, H=1, C=0. The JR Z
 * tail is an explicit boundary.
 */
__attribute__((noinline, used))
void port_print_bcd_digit(struct cpu_register_state *state)
{
	port_u8 a = (port_u8)(state->a & 0x0f);
	state->a = a;
	port_u8 z = (a == 0) ? 0x80 : 0;
	state->f = (port_u8)(z | 0x20);
}
