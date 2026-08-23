#include "port_state.h"

#define R_BGP 0xFF47u

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

static void
animation_flash_delay(struct cpu_register_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*state = delay.registers;
}

/* Port of AnimationFlashScreen in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_flash_screen(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_a = memory[R_BGP];
	port_u8 saved_f = state->f;

	state->a = saved_a;
	state->a = 0x1B;
	memory[R_BGP] = state->a;
	state->c = 2;
	animation_flash_delay(state);

	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[R_BGP] = state->a;
	state->c = 2;
	animation_flash_delay(state);

	state->a = saved_a;
	state->f = saved_f;
	memory[R_BGP] = state->a;
}
