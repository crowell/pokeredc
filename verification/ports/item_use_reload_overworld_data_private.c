#include "port_state.h"

struct item_use_reload_overworld_data_private_state {
	struct cpu_register_state registers;
};

/* Port of ItemUseReloadOverworldData through LoadCurrentMapView entry. */
__attribute__((noinline, used)) void
port_item_use_reload_overworld_data_private(
	struct item_use_reload_overworld_data_private_state *state)
{
	(void)state;
}
