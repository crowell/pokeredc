#include "port_state.h"

struct cable_club_do_battle_or_trade_private_state {
	struct cpu_register_state registers;
};

/* Port of CableClub_DoBattleOrTrade through DelayFrames entry. */
__attribute__((noinline, used)) void
port_cable_club_do_battle_or_trade_private(
	struct cable_club_do_battle_or_trade_private_state *state)
{
	state->registers.c = 80;
}
