#include "port_state.h"

struct load_town_map_fly_private_state {
	struct cpu_register_state registers;
};

/* Port of LoadTownMap_Fly through ClearSprites entry. */
__attribute__((noinline, used)) void
port_load_town_map_fly_private(struct load_town_map_fly_private_state *state)
{
	(void)state;
}
