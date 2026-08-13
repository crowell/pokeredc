#include "port_state.h"

static void
stats_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
stats_srl(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	*value >>= 1;
	registers->f = 0;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 1) != 0)
		registers->f |= PORT_FLAG_C;
}

static void
stats_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;

	registers->c--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
stats_advance_hl(struct cpu_register_state *registers)
{
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);

	hl = (port_u16)(hl + 2);
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
}

static void
stats_begin(struct selected_stats_state *state, port_u8 player_address_low,
	port_u8 enemy_address_low)
{
	state->registers.a = state->whose_turn;
	stats_and_a(&state->registers);
	state->registers.a = state->player_mask;
	state->registers.h = 0xd0;
	state->registers.l = player_address_low;
	if (state->whose_turn != 0) {
		state->registers.a = state->enemy_mask;
		state->registers.h = 0xcf;
		state->registers.l = enemy_address_low;
	}
	state->registers.c = 4;
	state->registers.b = state->registers.a;
}

__attribute__((noinline, used)) void
port_double_selected_stats_begin(struct selected_stats_state *state)
{
	stats_begin(state, 0x26, 0xf7);
}

__attribute__((noinline, used)) port_u8
port_double_selected_stats_step(struct selected_stats_state *state)
{
	port_u8 carry;
	port_u8 old;
	port_u16 wide;

	stats_srl(&state->registers, &state->registers.b);
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		old = state->stat_low;
		wide = (port_u16)old + old;
		state->registers.a = (port_u8)wide;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 0x0f) + (old & 0x0f) > 0x0f)
			state->registers.f |= PORT_FLAG_H;
		if (wide > 0xff)
			state->registers.f |= PORT_FLAG_C;
		state->stat_low = state->registers.a;
		carry = (state->registers.f & PORT_FLAG_C) != 0;
		old = state->stat_high;
		state->registers.a = (port_u8)((old << 1) | carry);
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 0x80) != 0)
			state->registers.f |= PORT_FLAG_C;
		state->stat_high = state->registers.a;
	}
	stats_advance_hl(&state->registers);
	stats_dec_c(&state->registers);
	return state->registers.c == 0;
}

/* Port of DoubleSelectedStats in engine/battle/unused_stats_functions.asm. */
__attribute__((noinline, used)) void
port_double_selected_stats(struct selected_stats_state *state, port_u8 stats[8])
{
	port_u8 index;

	port_double_selected_stats_begin(state);
	for (index = 0; index < 4; index++) {
		state->stat_high = stats[index * 2];
		state->stat_low = stats[index * 2 + 1];
		port_double_selected_stats_step(state);
		stats[index * 2] = state->stat_high;
		stats[index * 2 + 1] = state->stat_low;
	}
}

__attribute__((noinline, used)) void
port_halve_selected_stats_begin(struct selected_stats_state *state)
{
	stats_begin(state, 0x25, 0xf6);
}

__attribute__((noinline, used)) port_u8
port_halve_selected_stats_step(struct selected_stats_state *state)
{
	port_u8 carry;
	port_u8 old;

	stats_srl(&state->registers, &state->registers.b);
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		state->registers.a = state->stat_high;
		stats_srl(&state->registers, &state->registers.a);
		state->stat_high = state->registers.a;
		carry = (state->registers.f & PORT_FLAG_C) != 0;
		old = state->stat_low;
		state->stat_low = (port_u8)((old >> 1) | (carry << 7));
		state->registers.f = 0;
		if (state->stat_low == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 1) != 0)
			state->registers.f |= PORT_FLAG_C;
		state->registers.a |= state->stat_low;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if (state->registers.a == 0)
			state->stat_low = 1;
	}
	stats_advance_hl(&state->registers);
	stats_dec_c(&state->registers);
	return state->registers.c == 0;
}

/* Port of HalveSelectedStats in engine/battle/unused_stats_functions.asm. */
__attribute__((noinline, used)) void
port_halve_selected_stats(struct selected_stats_state *state, port_u8 stats[8])
{
	port_u8 index;

	port_halve_selected_stats_begin(state);
	for (index = 0; index < 4; index++) {
		state->stat_high = stats[index * 2];
		state->stat_low = stats[index * 2 + 1];
		port_halve_selected_stats_step(state);
		stats[index * 2] = state->stat_high;
		stats[index * 2 + 1] = state->stat_low;
	}
}
