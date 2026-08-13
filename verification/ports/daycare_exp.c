#include "port_state.h"

static port_u8
increment_exp_byte(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	(*value)++;
	registers->f &= PORT_FLAG_C;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
	return *value;
}

/* Port of IncrementDayCareMonExp in engine/overworld/daycare_exp.asm. */
__attribute__((noinline, used)) void
port_increment_daycare_mon_exp(struct daycare_exp_state *state)
{
	state->registers.a = state->in_use;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}
	state->registers.h = 0xda;
	state->registers.l = 0x6f;
	if (increment_exp_byte(&state->registers, &state->exp_low) != 0)
		return;
	state->registers.l--;
	if (increment_exp_byte(&state->registers, &state->exp_mid) != 0)
		return;
	state->registers.l--;
	increment_exp_byte(&state->registers, &state->exp_high);
	state->registers.a = state->exp_high;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0x50)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a < 0x50) {
		state->registers.f |= PORT_FLAG_C;
		return;
	}
	state->registers.a = 0x50;
	state->exp_high = state->registers.a;
}
