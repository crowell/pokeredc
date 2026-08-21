#include "port_state.h"

struct load_town_map_nest_private_state {
	struct cpu_register_state registers;
};

/* Port of LoadTownMap_Nest through LoadTownMap entry. */
__attribute__((noinline, used)) void
port_load_town_map_nest_private(struct load_town_map_nest_private_state *state)
{
	(void)state;
}
