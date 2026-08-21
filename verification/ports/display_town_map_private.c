#include "port_state.h"

struct display_town_map_private_state {
	struct cpu_register_state registers;
};

/* Port of DisplayTownMap through LoadTownMap entry. */
__attribute__((noinline, used)) void
port_display_town_map_private(struct display_town_map_private_state *state)
{
	(void)state;
}
