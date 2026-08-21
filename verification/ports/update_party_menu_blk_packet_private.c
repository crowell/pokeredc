#include "port_state.h"

struct update_party_menu_blk_private_state {
	struct cpu_register_state registers;
	port_u8 hp_bar_index;
};

/* Port of UpdatePartyMenuBlkPacket through palette-color pointer setup. */
__attribute__((noinline, used)) void
port_update_party_menu_blk_packet_private(
	struct update_party_menu_blk_private_state *state)
{
	state->registers.h = 0xcf;
	state->registers.l = 0x1f;
	state->registers.a = state->hp_bar_index;
	state->registers.d = 0;
	state->registers.e = state->hp_bar_index;
}
