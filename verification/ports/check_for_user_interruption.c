#include "port_state.h"
#include "joypad_port.h"

#define H_VBLANK_OCCURRED 0xffd6u
#define H_FRAMECOUNTER 0xffd5u

#define PAD_UP 0x40u
#define PAD_START 0x08u
#define PAD_SELECT 0x04u

void port_delay_frame(struct delay_frame_state *, const port_u8 *);

static void
check_for_user_interruption_delay(struct cpu_register_state *state,
	port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = memory[H_VBLANK_OCCURRED];
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
	memory[H_VBLANK_OCCURRED] = delay.vblank_occurred;
}

__attribute__((noinline, used)) void
port_check_for_user_interruption(struct cpu_register_state *state,
	port_u8 *memory)
{
	for (;;) {
		struct joypad_low_sensitivity_state joypad;
		port_u8 held;
		port_u8 pressed;

		check_for_user_interruption_delay(state, memory);

		joypad.joy7 = memory[H_JOY7];
		joypad.joy6 = memory[H_JOY6];
		joypad.pressed = memory[H_JOYPRESSED];
		joypad.held = memory[H_JOYHELD];
		joypad.joy5 = memory[H_JOY5];
		joypad.frame_counter = memory[H_FRAMECOUNTER];
		port_joypad_low_sensitivity(&joypad);
		memory[H_JOY5] = joypad.joy5;
		memory[H_FRAMECOUNTER] = joypad.frame_counter;

		held = memory[H_JOYHELD];
		state->a = held;
		if (held == PAD_UP + PAD_SELECT + PAD_B) {
			state->f = PORT_FLAG_Z | PORT_FLAG_C;
			return;
		}

		pressed = memory[H_JOY5] & (PAD_START | PAD_A);
		state->a = pressed;
		if (pressed != 0) {
			state->f = PORT_FLAG_C;
			return;
		}

		state->c--;
		if (state->c != 0)
			continue;

		state->f = PORT_FLAG_H | PORT_FLAG_Z;
		return;
	}
}
