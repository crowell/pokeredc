#include "port_state.h"

static port_u16
add_bcd_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
add_bcd_daa(struct cpu_register_state *registers)
{
	port_u8 correction = 0;
	port_u8 carry = registers->f & PORT_FLAG_C;

	if (carry != 0 || registers->a > 0x99) {
		correction |= 0x60;
		carry = PORT_FLAG_C;
	}
	if ((registers->f & PORT_FLAG_H) != 0 ||
	    (registers->a & 0x0f) > 9)
		correction |= 0x06;
	registers->a = (port_u8)(registers->a + correction);
	registers->f = carry;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
add_bcd_dec(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 carry = *flags & PORT_FLAG_C;

	(*value)--;
	*flags = (port_u8)(carry | PORT_FLAG_N);
	if (*value == 0)
		*flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		*flags |= PORT_FLAG_H;
}

__attribute__((noinline, used)) void
port_add_bcd_begin(struct add_bcd_state *state)
{
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.c;
}

/* Returns 1 for another digit, 2 for saturation fill, or 0 to return. */
__attribute__((noinline, used)) port_u8
port_add_bcd_step(struct add_bcd_state *state)
{
	port_u16 de = add_bcd_pair(state->registers.d, state->registers.e);
	port_u16 hl = add_bcd_pair(state->registers.h, state->registers.l);
	port_u8 left = state->fetched_left;
	port_u8 right = state->fetched_right;
	port_u8 carry = (state->registers.f & PORT_FLAG_C) != 0;
	port_u16 wide = (port_u16)left + right + carry;

	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	add_bcd_daa(&state->registers);
	state->written = state->registers.a;
	de--;
	hl--;
	add_bcd_dec(&state->registers.c, &state->registers.f);
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	if (state->registers.c != 0)
		return 1;
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		state->registers.a = 0x99;
		de++;
		state->registers.d = (port_u8)(de >> 8);
		state->registers.e = (port_u8)de;
		return 2;
	}
	return 0;
}

/* Returns one when the saturation fill is complete. */
__attribute__((noinline, used)) port_u8
port_add_bcd_fill_step(struct add_bcd_state *state)
{
	port_u16 de = add_bcd_pair(state->registers.d, state->registers.e);

	state->written = state->registers.a;
	de++;
	add_bcd_dec(&state->registers.b, &state->registers.f);
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return state->registers.b == 0;
}

/* Port of AddBCD in engine/math/bcd.asm. */
__attribute__((noinline, used)) void
port_add_bcd(struct add_bcd_state *state, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 de;
	port_u16 hl;

	port_add_bcd_begin(state);
	do {
		de = add_bcd_pair(state->registers.d, state->registers.e);
		hl = add_bcd_pair(state->registers.h, state->registers.l);
		state->fetched_left = memory[de];
		state->fetched_right = memory[hl];
		continuation = port_add_bcd_step(state);
		memory[de] = state->written;
	} while (continuation == 1);
	if (continuation == 2) {
		do {
			de = add_bcd_pair(state->registers.d, state->registers.e);
			continuation = port_add_bcd_fill_step(state);
			memory[de] = state->written;
		} while (continuation == 0);
	}
}
