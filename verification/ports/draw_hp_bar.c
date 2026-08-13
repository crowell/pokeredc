#include "port_state.h"

static port_u16
hp_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
hp_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)--;
	registers->f = carry | PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
hp_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

__attribute__((noinline, used)) void
port_draw_hp_bar_setup(struct draw_hp_bar_state *state)
{
	port_u16 hl = hp_pair(state->registers.h, state->registers.l);

	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	state->registers.a = 0x71;
	state->written0 = state->registers.a;
	hl++;
	state->registers.a = 0x62;
	state->written1 = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = 0x63;
}

/* Returns 1 to repeat, or 0 to draw the right cap. */
__attribute__((noinline, used)) port_u8
port_draw_hp_bar_empty_step(struct draw_hp_bar_state *state)
{
	port_u16 hl = hp_pair(state->registers.h, state->registers.l);

	state->written0 = state->registers.a;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	hp_dec(&state->registers, &state->registers.d);
	return state->registers.d != 0;
}

__attribute__((noinline, used)) void
port_draw_hp_bar_right(struct draw_hp_bar_state *state)
{
	state->registers.a = state->hp_bar_type;
	hp_dec(&state->registers, &state->registers.a);
	state->registers.a = 0x6d;
	if ((state->registers.f & PORT_FLAG_Z) == 0)
		hp_dec(&state->registers, &state->registers.a);
	state->written0 = state->registers.a;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	state->registers.h = state->saved_h;
	state->registers.l = (port_u8)(state->saved_l + 2);
	if (state->registers.l < state->saved_l)
		state->registers.h++;
}

/* Returns 1 to enter the fill recurrence, or 0 to finish. */
__attribute__((noinline, used)) port_u8
port_draw_hp_bar_select_fill(struct draw_hp_bar_state *state)
{
	state->registers.a = state->registers.e;
	hp_and_a(&state->registers);
	if (state->registers.a != 0)
		return 1;
	state->registers.a = state->registers.c;
	hp_and_a(&state->registers);
	if (state->registers.a == 0)
		return 0;
	state->registers.e = 1;
	return 1;
}

/* Returns 1 to repeat, or 0 after a partial/full terminal tile. */
__attribute__((noinline, used)) port_u8
port_draw_hp_bar_fill_step(struct draw_hp_bar_state *state)
{
	port_u16 hl;
	port_u8 left;
	unsigned int wide;

	state->registers.a = state->registers.e;
	left = state->registers.a;
	state->registers.a -= 8;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < 8)
		state->registers.f |= PORT_FLAG_H;
	if (left < 8)
		state->registers.f |= PORT_FLAG_C;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	if (left < 8) {
		state->registers.a = 0x63;
		wide = (unsigned int)state->registers.a + state->registers.e;
		state->registers.a = (port_u8)wide;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((0x63 & 0x0f) + (state->registers.e & 0x0f) > 0x0f)
			state->registers.f |= PORT_FLAG_H;
		if (wide > 0xff)
			state->registers.f |= PORT_FLAG_C;
		state->written0 = state->registers.a;
		return 0;
	}
	state->registers.e = state->registers.a;
	state->registers.a = 0x6b;
	state->written0 = state->registers.a;
	hl = (port_u16)(hp_pair(state->registers.h, state->registers.l) + 1);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->registers.e;
	hp_and_a(&state->registers);
	return state->registers.a != 0;
}

__attribute__((noinline, used)) void
port_draw_hp_bar_finish(struct draw_hp_bar_state *state)
{
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
}

/* Port of DrawHPBar in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_draw_hp_bar(struct draw_hp_bar_state *state, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 address;

	port_draw_hp_bar_setup(state);
	address = hp_pair(state->write_h, state->write_l);
	memory[address] = state->written0;
	memory[(port_u16)(address + 1)] = state->written1;
	do {
		continuation = port_draw_hp_bar_empty_step(state);
		address = hp_pair(state->write_h, state->write_l);
		memory[address] = state->written0;
	} while (continuation != 0);
	port_draw_hp_bar_right(state);
	address = hp_pair(state->write_h, state->write_l);
	memory[address] = state->written0;
	continuation = port_draw_hp_bar_select_fill(state);
	while (continuation != 0) {
		continuation = port_draw_hp_bar_fill_step(state);
		address = hp_pair(state->write_h, state->write_l);
		memory[address] = state->written0;
	}
	port_draw_hp_bar_finish(state);
}
