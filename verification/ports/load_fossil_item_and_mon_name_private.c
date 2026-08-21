#include "port_state.h"

struct load_fossil_name_private_state {
	struct cpu_register_state registers;
	port_u8 fossil_mon;
	port_u8 named_object_index;
};

/* Port of LoadFossilItemAndMonName through mon-name lookup setup. */
__attribute__((noinline, used)) void
port_load_fossil_item_and_mon_name_private(
	struct load_fossil_name_private_state *state)
{
	state->registers.a = state->fossil_mon;
	state->named_object_index = state->fossil_mon;
}
