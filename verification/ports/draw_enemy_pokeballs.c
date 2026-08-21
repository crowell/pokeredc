#include "port_state.h"

extern void port_load_party_pokeball_gfx(struct cpu_register_state *registers);
extern void port_setup_enemy_party_pokeballs(struct cpu_register_state *registers);

/* Port of DrawEnemyPokeballs: ordered graphics and enemy setup calls. */
__attribute__((noinline, used)) void
port_draw_enemy_pokeballs(struct cpu_register_state *registers)
{
	port_load_party_pokeball_gfx(registers);
	port_setup_enemy_party_pokeballs(registers);
}
