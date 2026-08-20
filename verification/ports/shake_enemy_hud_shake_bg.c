#include "port_state.h"

struct shake_enemy_hud_state {
	struct cpu_register_state registers;
	port_u8 scx;
	port_u8 temp_scx;
};

static port_u8
add_flags(port_u8 left, port_u8 right, port_u8 result)
{
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if (((left & 0x0f) + (right & 0x0f)) > 0x0f)
		flags |= PORT_FLAG_H;
	if ((port_u16)left + right > 0xff)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of the first ShakeEnemyHUD_ShakeBG iteration through DelayFrames. */
__attribute__((noinline, used)) void
port_shake_enemy_hud_shake_bg(struct shake_enemy_hud_state *state)
{
	port_u8 result;

	state->temp_scx = state->scx;
	result = (port_u8)(state->temp_scx + state->registers.d);
	state->scx = result;
	state->registers.a = result;
	state->registers.c = 2;
	state->registers.f = add_flags(state->temp_scx, state->registers.d, result);
}
