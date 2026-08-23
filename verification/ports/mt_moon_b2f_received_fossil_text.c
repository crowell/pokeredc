#include "port_state.h"

/* Port of MtMoonB2FReceivedFossilText in scripts/MtMoonB2F.asm:
 *
 *   ld hl, MtMoonB2FReceivedFossilText.Text
 *   jp PrintText
 */

void port_print_text(struct cpu_register_state *, port_u8 *);

#define MT_MOON_B2F_RECEIVED_FOSSIL_TEXT_HL 0x5f6fu

__attribute__((noinline, used)) void
port_mt_moon_b2f_received_fossil_text(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(MT_MOON_B2F_RECEIVED_FOSSIL_TEXT_HL >> 8);
	state->l = (port_u8)(MT_MOON_B2F_RECEIVED_FOSSIL_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
