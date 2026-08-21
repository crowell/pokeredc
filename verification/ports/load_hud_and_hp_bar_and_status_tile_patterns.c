#include "port_state.h"

struct load_hud_patterns_state {
	struct cpu_register_state registers;
	port_u8 lcd_control;
};

/* Port of LoadHudAndHpBarAndStatusTilePatterns through LCD selection. */
__attribute__((noinline, used)) void
port_load_hud_and_hp_bar_and_status_tile_patterns(struct load_hud_patterns_state *state)
{
	port_u8 old = state->lcd_control;
	port_u16 wide = (port_u16)old + old;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) + (old & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
}
