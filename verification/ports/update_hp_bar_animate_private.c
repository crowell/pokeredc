#include "port_state.h"

struct update_hp_bar_animate_private_state {
	struct cpu_register_state registers;
};

/* Port of UpdateHPBar_AnimateHPBar through animation-loop setup. */
__attribute__((noinline, used)) void
port_update_hp_bar_animate_private(
	struct update_hp_bar_animate_private_state *state)
{
	(void)state;
}
