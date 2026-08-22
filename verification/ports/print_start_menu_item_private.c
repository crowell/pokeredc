#include "port_state.h"

struct print_start_menu_item_private_state {
	struct cpu_register_state registers;
};

/* Port of PrintStartMenuItem through PlaceString entry. */
__attribute__((noinline, used)) void
port_print_start_menu_item_private(
	struct print_start_menu_item_private_state *state)
{
	(void)state;
}
