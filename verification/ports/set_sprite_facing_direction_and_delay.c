#include "port_state.h"

void port_set_sprite_facing_direction(struct cpu_register_state *state,
	port_u8 *memory);
void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

__attribute__((noinline, used)) void
port_set_sprite_facing_direction_and_delay(
	struct sprite_facing_direction_delay_state *state, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	port_set_sprite_facing_direction(&state->registers, memory);
	state->registers.c = 6;
	state->frames_waited = state->registers.c;
	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
}
