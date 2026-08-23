#include "port_state.h"

void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);
void port_clear_sprites(struct clear_sprites_state *state);

static void
animation_clean_delay(struct cpu_register_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
}

/* Port of AnimationCleanOAM in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_clean_oam(struct clear_sprites_state *state)
{
	struct cpu_register_state saved = state->registers;

	animation_clean_delay(&state->registers);
	port_clear_sprites(state);
	state->registers = saved;
}
