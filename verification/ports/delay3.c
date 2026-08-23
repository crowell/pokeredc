#include "port_state.h"

/* Port of Delay3 in home/palettes.asm. */
void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	(void)memory;
	state->c = 3;
	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*state = delay.registers;
}
