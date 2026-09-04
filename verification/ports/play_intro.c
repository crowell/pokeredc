#include "port_state.h"

void port_clear_sprites(struct clear_sprites_state *);
void port_delay_frame(struct delay_frame_state *, const port_u8 *);

#define H_JOY_HELD 0xffb4u
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define H_SCX 0xffaeu

/* PlayShootingStar and PlayIntroScene remain explicit call boundaries. */
__attribute__((noinline, used)) void
port_play_intro(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 observations[1] = {0};
	struct clear_sprites_state sprites = {0};
	struct delay_frame_state delay = {0};

	memory[H_JOY_HELD] = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;

	/* GBFadeOutToWhite is an explicit visual-effect boundary. */
	memory[H_SCX] = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;

	sprites.registers = *state;
	port_clear_sprites(&sprites);
	*state = sprites.registers;

	delay.registers = *state;
	port_delay_frame(&delay, observations);
	*state = delay.registers;
}
