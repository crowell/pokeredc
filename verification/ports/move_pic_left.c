#include "port_state.h"

/* Port of MovePicLeft in engine/movie/oak_speech/oak_speech.asm.
 *
 * It sets the window X position to 119, writes the background palette, then
 * decrements the window X each frame by 8 until the
 * next step would wrap to 0xFF, at which point it returns. The only observable
 * side effects are the rWX and rBGP hardware registers. */
#define R_WX 0xff4b
#define R_BGP 0xff47
#define START_X 119
#define STEP 8

void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);

static void
move_pic_left_delay_frame(struct cpu_register_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
}

__attribute__((noinline, used)) void
port_move_pic_left(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = START_X;
	memory[R_WX] = state->a;
	move_pic_left_delay_frame(state);
	state->a = 0xE4; /* %11100100 */
	memory[R_BGP] = state->a;
	for (;;) {
		move_pic_left_delay_frame(state);
		state->a = memory[R_WX];
		state->a = (port_u8)(state->a - STEP);
		if (state->a == 0xFF) {
			state->f = PORT_FLAG_N | PORT_FLAG_Z;
			return;
		}
		memory[R_WX] = state->a;
	}
}
