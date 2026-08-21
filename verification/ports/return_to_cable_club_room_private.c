#include "port_state.h"

struct return_to_cable_club_room_private_state {
	struct cpu_register_state registers;
};

/* Port of ReturnToCableClubRoom through palette white-out entry. */
__attribute__((noinline, used)) void
port_return_to_cable_club_room_private(
	struct return_to_cable_club_room_private_state *state)
{
	(void)state;
}
