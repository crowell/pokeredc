#include "port_state.h"

extern void port_load_party_pokeball_gfx(struct cpu_register_state *registers);
extern void port_setup_pokeballs(struct cpu_register_state *registers);

/* Port of SetupPlayerAndEnemyPokeballs through the final OAM writer call. */
__attribute__((noinline, used)) void
port_setup_player_and_enemy_pokeballs(struct cpu_register_state *registers)
{
	port_load_party_pokeball_gfx(registers);
	port_setup_pokeballs(registers);
	/* Player OAM setup is a continuation boundary before the enemy pass. */
	port_setup_pokeballs(registers);
	registers->a = 0x50;
	registers->h = 0xc3;
	registers->l = 0x18;
}
