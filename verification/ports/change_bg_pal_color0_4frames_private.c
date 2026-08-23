#include "port_state.h"

#define R_BGP 0xFF47u

void port_get_predef_registers(struct register_memory_state *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static void
change_bg_pal_delay(struct cpu_register_state *registers)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*registers = delay.registers;
}

/* Port of ChangeBGPalColor0_4Frames in engine/gfx/screen_effects.asm. */
__attribute__((noinline, used)) void
port_change_bg_pal_color0_4frames_private(
	struct register_memory_state *state, port_u8 *memory)
{
	struct register_memory_state predef;
	port_u8 result;
	port_u8 index;

	predef.registers = state->registers;
	for (index = 0; index < 6; index++)
		predef.memory[index] = state->memory[index];
	port_get_predef_registers(&predef);
	state->registers = predef.registers;

	state->registers.a = memory[R_BGP];
	result = (port_u8)(state->registers.a | state->registers.b);
	state->registers.a = result;
	state->registers.f = result == 0 ? PORT_FLAG_Z : 0;
	memory[R_BGP] = result;

	state->registers.c = 4;
	change_bg_pal_delay(&state->registers);

	result = (port_u8)(memory[R_BGP] & 0xFCu);
	state->registers.a = result;
	state->registers.f = PORT_FLAG_H;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	memory[R_BGP] = result;
}
