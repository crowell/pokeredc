#include "port_state.h"

struct hp_bar_length_private_state {
	struct cpu_register_state registers;
};

/* Port of HPBarLength through GetPredefRegisters continuation boundary. */
__attribute__((noinline, used)) void
port_hp_bar_length_private(struct hp_bar_length_private_state *state)
{
	(void)state;
}
