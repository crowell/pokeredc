#include "port_state.h"

void port_delay_frame(struct delay_frame_state *, const port_u8 *);

/* Port of OverworldLoop through its first DelayFrame call boundary. The
 * remainder of the interactive overworld dispatch remains outside this
 * proof domain. */
__attribute__((noinline, used)) void
port_overworld_loop(struct cpu_register_state *state)
{
	struct delay_frame_state delay = {0};
	const port_u8 observations[] = {0};

	delay.registers = *state;
	port_delay_frame(&delay, observations);
	*state = delay.registers;
}
