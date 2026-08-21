#include "port_state.h"

struct draw_enemy_hud_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

/* Port of DrawEnemyHUDAndHPBar setup through ClearScreenArea. */
__attribute__((noinline, used)) void
port_draw_enemy_hud_and_hp_bar(struct draw_enemy_hud_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_bg_transfer_enabled = 0;
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	state->registers.b = 4;
	state->registers.c = 12;
}
