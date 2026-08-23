#include "port_state.h"

void port_get_predef_registers(struct register_memory_state *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

__attribute__((noinline, used)) void
port_predef_shake_screen_vertically_mutate_wy(
	struct predef_shake_vertical_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;
	port_u8 result;

	state->registers.a = state->mutate_wy;
	result = (port_u8)(state->registers.a ^ state->registers.b);
	state->registers.a = result;
	state->registers.f = result == 0 ? PORT_FLAG_Z : 0;
	state->mutate_wy = result;
	state->wy = result;
	state->registers.c = 3;

	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
}

/* One complete .loop recurrence, including both .MutateWY calls. */
__attribute__((noinline, used)) port_u8
port_predef_shake_screen_vertically_step(
	struct predef_shake_vertical_state *state)
{
	port_u8 before;
	port_u8 result;
	port_u8 flags;

	state->mutate_wy = state->registers.a;
	port_predef_shake_screen_vertically_mutate_wy(state);
	port_predef_shake_screen_vertically_mutate_wy(state);

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
port_predef_shake_screen_vertically_loop(
	struct predef_shake_vertical_state *state)
{
	do {
	} while (port_predef_shake_screen_vertically_step(state));
}

/* Port of PredefShakeScreenVertically in engine/gfx/screen_effects.asm. */
__attribute__((noinline, used)) void
port_predef_shake_screen_vertically_private(
	struct predef_shake_vertical_state *state)
{
	struct register_memory_state predef;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->predef[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;

	state->registers.a = 1;
	state->disable_vblank_wy_update = 1;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	port_predef_shake_screen_vertically_loop(state);
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->disable_vblank_wy_update = 0;
}
