#include "port_state.h"

struct draw_player_hud_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

struct draw_enemy_hud_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer_enabled;
};

void port_draw_player_hud_and_hp_bar(struct draw_player_hud_state *state);
void port_draw_enemy_hud_and_hp_bar(struct draw_enemy_hud_state *state);

/* Port of DrawHUDsAndHPBars: call the player HUD, then the enemy HUD. */
__attribute__((noinline, used)) void
port_draw_huds_and_hp_bars(struct cpu_register_state *registers)
{
	struct draw_player_hud_state player = {*registers, 0};
	port_draw_player_hud_and_hp_bar(&player);
	*registers = player.registers;

	struct draw_enemy_hud_state enemy = {*registers, player.auto_bg_transfer_enabled};
	port_draw_enemy_hud_and_hp_bar(&enemy);
	*registers = enemy.registers;
}
