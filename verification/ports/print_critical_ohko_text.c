#include "port_state.h"

struct print_critical_ohko_state {
	struct cpu_register_state registers;
	port_u8 critical_hit_or_ohko;
	port_u8 delay_iterations;
};

void port_print_text(struct cpu_register_state *, port_u8 *);
port_u8 port_delay_frames_step(struct delay_frame_state *,
	const port_u8 *);

#define W_CRITICAL_HIT_OR_OHKO 0xd05eu
#define CRITICAL_HIT_TEXT 0x5c7eu
#define OHKO_TEXT 0x5c83u

/* Port of PrintCriticalOHKOText.  The fixed DelayFrames tail executes the
 * real DelayFrame/DEC-C transition through port_delay_frames_step. */
__attribute__((noinline, used)) void
port_print_critical_ohko_text(struct print_critical_ohko_state *state,
	port_u8 *memory, const port_u8 *observations)
{
	state->registers.a = state->critical_hit_or_ohko;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a != 0) {
		port_u16 text = state->registers.a == 1u ? CRITICAL_HIT_TEXT : OHKO_TEXT;
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
		port_print_text(&state->registers, memory);
		memory[W_CRITICAL_HIT_OR_OHKO] = 0;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}

	/* The function always tail-jumps to DelayFrames with C = 20. */
	{
		struct delay_frame_state delay = {0};
		delay.registers = state->registers;
		delay.registers.c = 20u;
		delay.observed_vblank = 0u;
		state->delay_iterations = 0u;
		do {
			state->delay_iterations++;
		} while (port_delay_frames_step(&delay, observations));
		state->registers = delay.registers;
	}
}
