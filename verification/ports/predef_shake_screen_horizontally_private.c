#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

__attribute__((noinline, used)) void
port_predef_shake_screen_horizontally_mutate_wx(
	struct predef_shake_horizontal_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;
	port_u8 left;
	port_u8 result;
	port_u8 flags;
	port_u16 wide;

	result = (port_u8)(state->mutate_wx ^ state->registers.b);
	state->registers.a = result;
	state->registers.f = result == 0 ? PORT_FLAG_Z : 0;
	state->mutate_wx = result;
	if (result & 0x80u) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}

	left = state->registers.a;
	wide = (port_u16)left + 7u;
	result = (port_u8)wide;
	flags = 0;
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0Fu) + 7u > 0x0Fu)
		flags |= PORT_FLAG_H;
	if (wide > 0xFFu)
		flags |= PORT_FLAG_C;
	state->registers.a = result;
	state->registers.f = flags;
	state->wx = result;
	state->registers.c = 4;

	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
}

__attribute__((noinline, used)) port_u8
port_predef_shake_screen_horizontally_step(
	struct predef_shake_horizontal_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;
	port_u8 before;
	port_u8 result;
	port_u8 flags;

	state->mutate_wx = state->registers.a;
	port_predef_shake_screen_horizontally_mutate_wx(state);
	state->registers.c = 1;
	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
	port_predef_shake_screen_horizontally_mutate_wx(state);

	before = state->registers.b;
	result = (port_u8)(before - 1);
	flags = (port_u8)((state->registers.f & PORT_FLAG_C) | PORT_FLAG_N);
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0Fu) == 0)
		flags |= PORT_FLAG_H;
	state->registers.b = result;
	state->registers.f = flags;
	state->registers.a = result;
	return result != 0;
}

__attribute__((noinline, used)) void
port_predef_shake_screen_horizontally_loop(
	struct predef_shake_horizontal_state *state)
{
	do {
	} while (port_predef_shake_screen_horizontally_step(state));
}

/* Port of PredefShakeScreenHorizontally in engine/gfx/screen_effects.asm. */
__attribute__((noinline, used)) void
port_predef_shake_screen_horizontally_private(
	struct predef_shake_horizontal_state *state)
{
	struct register_memory_state predef;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	port_predef_shake_screen_horizontally_loop(state);
	state->registers.a = 7;
	state->wx = 7;
}
