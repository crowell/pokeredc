#include "port_state.h"

struct ingame_trade_do_trade_private_state {
	struct cpu_register_state registers;
	port_u8 party_menu_type;
	port_u8 update_sprites;
};

/* Port of InGameTrade_DoTrade through DisplayPartyMenu setup. */
__attribute__((noinline, used)) void
port_ingame_trade_do_trade_private(
	struct ingame_trade_do_trade_private_state *state)
{
	state->registers.a = 0xff;
	state->registers.f = 0;
	state->party_menu_type = 0;
	state->update_sprites = 0xff;
}
