#include "port_state.h"

#define IMPP_H_WHOSE_TURN 0xfff3u
#define IMPP_W_BATTLE_MON_PP 0xd02du
#define IMPP_W_PARTY_MON1_PP 0xd188u
#define IMPP_W_ENEMY_MON_PP 0xcffeu
#define IMPP_W_ENEMY_MON1_PP 0xd8c1u
#define IMPP_W_PLAYER_MOVE_LIST_INDEX 0xcc2eu
#define IMPP_W_PLAYER_MON_NUMBER 0xcc2fu
#define IMPP_W_ENEMY_MOVE_LIST_INDEX 0xcce2u
#define IMPP_W_ENEMY_MON_PARTY_POS 0xcfe8u
#define IMPP_PARTYMON_STRUCT_LENGTH 0x2cu

void port_add_n_times(struct cpu_register_state *state);

static void
set_and_a_flags(struct cpu_register_state *state)
{
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
}

static void
add_hl_bc(struct cpu_register_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u16 bc = (port_u16)(((port_u16)state->b << 8) | state->c);
	port_u32 result = (port_u32)hl + bc;
	port_u8 flags = (port_u8)(state->f & PORT_FLAG_Z);
	if ((hl & 0x0fff) + (bc & 0x0fff) > 0x0fff)
		flags |= PORT_FLAG_H;
	if (result > 0xffff)
		flags |= PORT_FLAG_C;
	state->h = (port_u8)(result >> 8);
	state->l = (port_u8)result;
	state->f = flags;
}

static void
increment_at_hl(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u8 old = memory[hl];
	memory[hl]++;
	state->f &= PORT_FLAG_C;
	if (memory[hl] == 0)
		state->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		state->f |= PORT_FLAG_H;
}

/* Port of IncrementMovePP in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_increment_move_pp(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 whose = memory[IMPP_H_WHOSE_TURN];
	state->a = whose;
	set_and_a_flags(state);
	if (whose == 0) {
		state->h = (port_u8)(IMPP_W_BATTLE_MON_PP >> 8);
		state->l = (port_u8)IMPP_W_BATTLE_MON_PP;
		state->d = (port_u8)(IMPP_W_PARTY_MON1_PP >> 8);
		state->e = (port_u8)IMPP_W_PARTY_MON1_PP;
		state->a = memory[IMPP_W_PLAYER_MOVE_LIST_INDEX];
	} else {
		state->h = (port_u8)(IMPP_W_ENEMY_MON_PP >> 8);
		state->l = (port_u8)IMPP_W_ENEMY_MON_PP;
		state->d = (port_u8)(IMPP_W_ENEMY_MON1_PP >> 8);
		state->e = (port_u8)IMPP_W_ENEMY_MON1_PP;
		state->a = memory[IMPP_W_ENEMY_MOVE_LIST_INDEX];
	}
	state->b = 0;
	state->c = state->a;
	add_hl_bc(state);
	increment_at_hl(state, memory);
	state->h = state->d;
	state->l = state->e;
	add_hl_bc(state);
	state->a = whose;
	set_and_a_flags(state);
	state->a = (whose == 0)
		? memory[IMPP_W_PLAYER_MON_NUMBER]
		: memory[IMPP_W_ENEMY_MON_PARTY_POS];
	state->b = 0;
	state->c = IMPP_PARTYMON_STRUCT_LENGTH;
	port_add_n_times(state);
	increment_at_hl(state, memory);
}
