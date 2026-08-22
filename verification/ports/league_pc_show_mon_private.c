#include "port_state.h"

struct league_pc_show_mon_private_state {
	struct cpu_register_state registers;
	port_u8 hall_of_fame_species;
	port_u8 hall_of_fame_level;
	port_u8 hof_mon_species;
	port_u8 cur_party_species;
	port_u8 cur_species;
	port_u8 battle_mon_species2;
	port_u8 whole_screen_palette_mon_species;
	port_u8 hof_mon_level;
};

/* Port of LeaguePCShowMon through CopyData dispatch. */
__attribute__((noinline, used)) void
port_league_pc_show_mon_private(struct league_pc_show_mon_private_state *state)
{
	port_u8 species = state->hall_of_fame_species;
	port_u8 level = state->hall_of_fame_level;

	state->hof_mon_species = species;
	state->cur_party_species = species;
	state->cur_species = species;
	state->battle_mon_species2 = species;
	state->whole_screen_palette_mon_species = species;
	state->hof_mon_level = level;
	state->registers.a = level;
	state->registers.d = 0xcd;
	state->registers.e = 0x6d;
	state->registers.b = 0;
	state->registers.c = 11;
}
