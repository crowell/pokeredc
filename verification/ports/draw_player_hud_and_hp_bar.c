#include "port_state.h"

struct draw_player_hud_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of DrawPlayerHUDAndHPBar setup through ClearScreenArea. */
__attribute__((noinline, used)) void
port_draw_player_hud_and_hp_bar(struct draw_player_hud_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_bg_transfer_enabled = 0;
	state->registers.h = 0xc4;
	state->registers.l = 0x35;
	state->registers.b = 5;
	state->registers.c = 11;
}
