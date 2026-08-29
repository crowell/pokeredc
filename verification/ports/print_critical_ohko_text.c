#include "port_state.h"

struct print_critical_ohko_state {
	struct cpu_register_state registers;
	port_u8 critical_hit_or_ohko;
};

void port_print_text(struct cpu_register_state *, port_u8 *);

#define W_CRITICAL_HIT_OR_OHKO 0xd05eu
#define CRITICAL_HIT_TEXT 0x5c7eu
#define OHKO_TEXT 0x5c83u

/* Port of PrintCriticalOHKOText.  DelayFrames is represented by the
 * terminal frame boundary used by the focused proof. */
__attribute__((noinline, used)) void
port_print_critical_ohko_text(struct print_critical_ohko_state *state,
	port_u8 *memory)
{
	state->registers.a = state->critical_hit_or_ohko;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	} else {
		port_u16 text = state->registers.a == 1u ? CRITICAL_HIT_TEXT : OHKO_TEXT;
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
		port_print_text(&state->registers, memory);
		memory[W_CRITICAL_HIT_OR_OHKO] = 0;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
	/* The function always tail-jumps to DelayFrames with C = 20.  The
	 * terminal delay boundary leaves C at zero and the final DEC flags. */
	state->registers.c = 0;
	state->registers.f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);
}
