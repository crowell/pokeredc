#include "port_state.h"

static port_u16
redraw_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
redraw_inc_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a++;
	registers->f = carry;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
redraw_dec(struct cpu_register_state *registers, port_u8 *value)
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
redraw_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	unsigned int wide = (unsigned int)left + right;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

/* Returns 0 for disabled, 1 for column, or 2 for row. */
__attribute__((noinline, used)) port_u8
port_redraw_row_or_column_setup(struct redraw_row_column_state *state)
{
	state->registers.a = state->mode;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0)
		return 0;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->mode = state->registers.a;
	redraw_dec(&state->registers, &state->registers.b);
	state->registers.h = 0xcb;
	state->registers.l = 0xfc;
	state->registers.a = state->dest_low;
	state->registers.e = state->registers.a;
	state->registers.a = state->dest_high;
	state->registers.d = state->registers.a;
	if (state->registers.b == 0) {
		state->registers.c = 18;
		return 1;
	}
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->registers.c = 10;
	return 2;
}

/* Returns 1 for another column pair or 0 after clearing the mode. */
__attribute__((noinline, used)) port_u8
port_redraw_column_step(struct redraw_row_column_state *state)
{
	port_u16 hl = redraw_pair(state->registers.h, state->registers.l);
	port_u16 de = redraw_pair(state->registers.d, state->registers.e);
	port_u8 old_c;
	port_u8 carry;

	state->registers.a = state->fetched0;
	hl++;
	state->written0 = state->registers.a;
	state->write_h0 = (port_u8)(de >> 8);
	state->write_l0 = (port_u8)de;
	de++;
	state->registers.a = state->fetched1;
	hl++;
	state->written1 = state->registers.a;
	state->write_h1 = (port_u8)(de >> 8);
	state->write_l1 = (port_u8)de;
	state->registers.a = 31;
	redraw_add_a(&state->registers, (port_u8)de);
	state->registers.e = state->registers.a;
	carry = state->registers.f & PORT_FLAG_C;
	state->registers.d = (port_u8)(de >> 8);
	if (carry)
		state->registers.d++;
	state->registers.a = state->registers.d;
	state->registers.a &= 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a |= 0x98;
	state->registers.f = 0;
	state->registers.d = state->registers.a;
	old_c = state->registers.c;
	redraw_dec(&state->registers, &state->registers.c);
	(void)old_c;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	if (state->registers.c != 0)
		return 1;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->mode = state->registers.a;
	return 0;
}

/* Returns 1 for another two-byte half-row pair or 0 at RET. */
__attribute__((noinline, used)) port_u8
port_redraw_row_half_step(struct redraw_row_column_state *state)
{
	port_u16 hl = redraw_pair(state->registers.h, state->registers.l);
	port_u16 de = redraw_pair(state->registers.d, state->registers.e);
	port_u8 old_c;

	state->registers.a = state->fetched0;
	hl++;
	state->written0 = state->registers.a;
	state->write_h0 = (port_u8)(de >> 8);
	state->write_l0 = (port_u8)de;
	de++;
	state->registers.a = state->fetched1;
	hl++;
	state->written1 = state->registers.a;
	state->write_h1 = (port_u8)(de >> 8);
	state->write_l1 = (port_u8)de;
	state->registers.a = (port_u8)de;
	redraw_inc_a(&state->registers);
	state->registers.a &= 31;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.a;
	state->registers.a = (port_u8)de;
	state->registers.a &= 0xe0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a |= state->registers.b;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.e = state->registers.a;
	state->registers.d = (port_u8)(de >> 8);
	old_c = state->registers.c;
	redraw_dec(&state->registers, &state->registers.c);
	(void)old_c;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.c == 0 ? 0 : 1;
}

__attribute__((noinline, used)) void
port_redraw_row_between_halves(struct redraw_row_column_state *state)
{
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.a = 32;
	redraw_add_a(&state->registers, state->registers.e);
	state->registers.e = state->registers.a;
	state->registers.c = 10;
}

/* Port of RedrawRowOrColumn in home/vcopy.asm. */
__attribute__((noinline, used)) void
port_redraw_row_or_column(struct redraw_row_column_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_redraw_row_or_column_setup(state);
	port_u16 source;
	port_u16 address;

	if (continuation == 0)
		return;
	if (continuation == 1) {
		do {
			source = redraw_pair(state->registers.h, state->registers.l);
			state->fetched0 = memory[source];
			state->fetched1 = memory[(port_u16)(source + 1)];
			continuation = port_redraw_column_step(state);
			address = redraw_pair(state->write_h0, state->write_l0);
			memory[address] = state->written0;
			address = redraw_pair(state->write_h1, state->write_l1);
			memory[address] = state->written1;
		} while (continuation != 0);
		return;
	}
	do {
		source = redraw_pair(state->registers.h, state->registers.l);
		state->fetched0 = memory[source];
		state->fetched1 = memory[(port_u16)(source + 1)];
		continuation = port_redraw_row_half_step(state);
		address = redraw_pair(state->write_h0, state->write_l0);
		memory[address] = state->written0;
		address = redraw_pair(state->write_h1, state->write_l1);
		memory[address] = state->written1;
	} while (continuation != 0);
	port_redraw_row_between_halves(state);
	do {
		source = redraw_pair(state->registers.h, state->registers.l);
		state->fetched0 = memory[source];
		state->fetched1 = memory[(port_u16)(source + 1)];
		continuation = port_redraw_row_half_step(state);
		address = redraw_pair(state->write_h0, state->write_l0);
		memory[address] = state->written0;
		address = redraw_pair(state->write_h1, state->write_l1);
		memory[address] = state->written1;
	} while (continuation != 0);
}
