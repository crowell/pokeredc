#include "port_state.h"

static void
badge_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
badge_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->c--;
	registers->f = carry | PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Returns 0 for link battles or 1 to enter the four-stat recurrence. */
__attribute__((noinline, used)) port_u8
port_apply_badge_stat_boosts_setup(struct badge_stat_boost_state *state)
{
	state->registers.a = state->link_state;
	badge_cp(&state->registers, 4);
	if (state->registers.a == 4)
		return 0;
	state->registers.a = state->badges;
	state->registers.b = state->registers.a;
	state->registers.h = 0xd0;
	state->registers.l = 0x25;
	state->registers.c = 4;
	return 1;
}

/* Exact .applyBoostToStat helper. */
__attribute__((noinline, used)) void
port_apply_badge_boost_to_stat(struct badge_stat_boost_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 carry;
	port_u8 left;
	port_u8 right;
	port_u8 old;
	unsigned int wide;

	state->registers.a = state->stat_high;
	hl++;
	state->registers.d = state->registers.a;
	state->registers.e = state->stat_low;
	for (old = 0; old < 3; old++) {
		left = state->registers.d;
		state->registers.d >>= 1;
		state->registers.f = state->registers.d == 0 ? PORT_FLAG_Z : 0;
		if (left & 1)
			state->registers.f |= PORT_FLAG_C;
		left = state->registers.e;
		carry = state->registers.f & PORT_FLAG_C;
		state->registers.e = (port_u8)((left >> 1) |
			(carry ? 0x80 : 0));
		state->registers.f = state->registers.e == 0 ? PORT_FLAG_Z : 0;
		if (left & 1)
			state->registers.f |= PORT_FLAG_C;
	}
	state->registers.a = state->stat_low;
	left = state->registers.a;
	right = state->registers.e;
	wide = (unsigned int)left + right;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->stat_low = state->registers.a;
	hl--;
	state->registers.a = state->stat_high;
	left = state->registers.a;
	right = state->registers.d;
	carry = state->registers.f & PORT_FLAG_C;
	wide = (unsigned int)left + right + (carry ? 1 : 0);
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + (carry ? 1 : 0) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->stat_high = state->registers.a;
	hl++;
	state->registers.a = state->stat_low;
	hl--;
	left = state->registers.a;
	state->registers.a -= 0xe7;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < 7)
		state->registers.f |= PORT_FLAG_H;
	if (left < 0xe7)
		state->registers.f |= PORT_FLAG_C;
	state->registers.a = state->stat_high;
	left = state->registers.a;
	carry = state->registers.f & PORT_FLAG_C;
	state->registers.a = (port_u8)(left - 3 - (carry ? 1 : 0));
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (port_u8)(3 + (carry ? 1 : 0)))
		state->registers.f |= PORT_FLAG_H;
	if (left < (port_u8)(3 + (carry ? 1 : 0)))
		state->registers.f |= PORT_FLAG_C;
	if ((state->registers.f & PORT_FLAG_C) == 0) {
		state->registers.a = 3;
		state->stat_high = state->registers.a;
		hl++;
		state->registers.a = 0xe7;
		state->stat_low = state->registers.a;
		hl--;
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) port_u8
port_apply_badge_stat_boosts_dispatch(struct badge_stat_boost_state *state)
{
	port_u8 value = state->registers.b;

	state->registers.b >>= 1;
	state->registers.f = state->registers.b == 0 ? PORT_FLAG_Z : 0;
	if (value & 1)
		state->registers.f |= PORT_FLAG_C;
	return value & 1;
}

/* Returns 1 for another stat or 0 after the fourth. */
__attribute__((noinline, used)) port_u8
port_apply_badge_stat_boosts_advance(struct badge_stat_boost_state *state)
{
	port_u16 hl;
	port_u8 value;

	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	hl += 2;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	value = state->registers.b;
	state->registers.b >>= 1;
	state->registers.f = state->registers.b == 0 ? PORT_FLAG_Z : 0;
	if (value & 1)
		state->registers.f |= PORT_FLAG_C;
	badge_dec_c(&state->registers);
	return state->registers.c == 0 ? 0 : 1;
}

/* Port of ApplyBadgeStatBoosts in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_apply_badge_stat_boosts(struct badge_stat_boost_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_apply_badge_stat_boosts_setup(state);
	port_u8 boost;
	port_u16 address;

	while (continuation != 0) {
		address = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->stat_high = memory[address];
		state->stat_low = memory[(port_u16)(address + 1)];
		boost = port_apply_badge_stat_boosts_dispatch(state);
		if (boost) {
			port_apply_badge_boost_to_stat(state);
			memory[address] = state->stat_high;
			memory[(port_u16)(address + 1)] = state->stat_low;
		}
		continuation = port_apply_badge_stat_boosts_advance(state);
	}
}
