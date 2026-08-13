#include "port_state.h"

/* Port of AnyPartyAlive in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_any_party_alive(struct party_alive_state *state)
{
	port_u8 index = 0;

	state->registers.a = state->party_count;
	state->registers.e = state->registers.a;
	state->registers.a = 0;
	state->registers.h = 0xd1;
	state->registers.l = 0x6c;
	state->registers.b = 0;
	state->registers.c = 0x2b;
	do {
		state->registers.a |= state->party_hp[index++];
		state->registers.a |= state->party_hp[index++];
		{
			port_u16 hl = ((port_u16)state->registers.h << 8) |
				state->registers.l;
			hl += 0x2c;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
		}
		state->registers.e--;
	} while (state->registers.e != 0);
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	state->registers.d = state->registers.a;
}

/* Port of AnyEnemyPokemonAliveCheck in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_any_enemy_pokemon_alive_check(struct party_alive_state *state)
{
	port_u8 index = 0;

	state->registers.a = state->party_count;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.h = 0xd8;
	state->registers.l = 0xa5;
	state->registers.d = 0;
	state->registers.e = 0x2c;
	do {
		state->registers.a |= state->party_hp[index++];
		state->registers.a |= state->party_hp[index++];
		{
			port_u16 hl = ((port_u16)state->registers.h << 8) |
				state->registers.l;
			hl += 0x2c;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
		}
		state->registers.b--;
	} while (state->registers.b != 0);
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
