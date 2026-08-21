#include "port_state.h"

void port_draw_huds_and_hp_bars(struct cpu_register_state *registers);

/* Port of ApplyAttackToPlayerPokemonDone: JP DrawHUDsAndHPBars. */
__attribute__((noinline, used)) void
port_apply_attack_to_player_pokemon_done(struct cpu_register_state *registers)
{
	port_draw_huds_and_hp_bars(registers);
}
