#include "port_state.h"

struct cable_club_do_battle_or_trade_again_private_state {
	struct cpu_register_state registers;
};

/* Port of CableClub_DoBattleOrTradeAgain through preamble-loop setup. */
__attribute__((noinline, used)) void
port_cable_club_do_battle_or_trade_again_private(
	struct cable_club_do_battle_or_trade_again_private_state *state)
{
	state->registers.h = 0xd1;
	state->registers.l = 0x52;
	state->registers.a = 0xfd;
	state->registers.b = 6;
}
