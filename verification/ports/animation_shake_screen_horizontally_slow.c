#include "port_state.h"

void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static void
slow_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 before = *value;

	(*value)--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
slow_inc_a(struct cpu_register_state *registers)
{
	port_u8 before = registers->a;

	registers->a++;
	registers->f &= PORT_FLAG_C;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
slow_dec_a(struct cpu_register_state *registers)
{
	slow_dec(registers, &registers->a);
}

static void
slow_delay(struct animation_shake_horizontal_slow_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = state->registers;
	delay.vblank_occurred = state->vblank_occurred;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
	state->vblank_occurred = delay.vblank_occurred;
}

/* Port of AnimationShakeScreenHorizontallySlow. */
__attribute__((noinline, used)) void
port_animation_shake_screen_horizontally_slow(
	struct animation_shake_horizontal_slow_state *state)
{
	port_u8 saved_b;
	port_u8 saved_c;

	do {
		saved_b = state->registers.b;
		saved_c = state->registers.c;
		do {
			state->registers.a = state->wx;
			slow_inc_a(&state->registers);
			state->wx = state->registers.a;
			state->registers.c = 2;
			slow_delay(state);
			slow_dec(&state->registers, &state->registers.b);
		} while (state->registers.b != 0);
		state->registers.b = saved_b;
		state->registers.c = saved_c;
		do {
			state->registers.a = state->wx;
			slow_dec_a(&state->registers);
			state->wx = state->registers.a;
			state->registers.c = 2;
			slow_delay(state);
			slow_dec(&state->registers, &state->registers.b);
		} while (state->registers.b != 0);
		state->registers.b = saved_b;
		state->registers.c = saved_c;
		slow_dec(&state->registers, &state->registers.c);
	} while (state->registers.c != 0);
}
