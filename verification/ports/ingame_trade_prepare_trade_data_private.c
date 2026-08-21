#include "port_state.h"

struct ingame_trade_prepare_data_private_state {
	struct cpu_register_state registers;
	port_u8 give_species;
	port_u8 receive_species;
	port_u8 traded_player_species;
	port_u8 traded_enemy_species;
};

/* Port of InGameTrade_PrepareTradeData through species setup. */
__attribute__((noinline, used)) void
port_ingame_trade_prepare_trade_data_private(
	struct ingame_trade_prepare_data_private_state *state)
{
	state->registers.a = state->receive_species;
	state->registers.h = 0xcd;
	state->registers.l = 0x3e;
	state->traded_player_species = state->give_species;
	state->traded_enemy_species = state->receive_species;
}
