#include "port_state.h"

struct remove_guard_drink_private_state {
	struct cpu_register_state registers;
};

/* Port of RemoveGuardDrink through GuardDrinksList setup. */
__attribute__((noinline, used)) void
port_remove_guard_drink_private(struct remove_guard_drink_private_state *state)
{
	state->registers.h = 0x65;
	state->registers.l = 0xb7;
}
