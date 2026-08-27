#include "port_state.h"

static port_u16
print_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
print_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8); r->l = (port_u8)value;
}

static void
print_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
print_sub(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->a = (port_u8)(left - right); r->f = PORT_FLAG_N;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
print_inc(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value; port_u8 carry = r->f & PORT_FLAG_C;
	(*value)++; r->f = carry;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
print_dec(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value; port_u8 carry = r->f & PORT_FLAG_C;
	(*value)--; r->f = carry | PORT_FLAG_N;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
print_or(struct cpu_register_state *r, port_u8 right)
{
	r->a |= right; r->f = r->a == 0 ? PORT_FLAG_Z : 0;
}

static void
print_and(struct cpu_register_state *r, port_u8 right)
{
	r->a &= right; r->f = PORT_FLAG_H | (r->a == 0 ? PORT_FLAG_Z : 0);
}

static void
print_add(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a; unsigned wide = (unsigned)left + right;
	r->a = (port_u8)wide; r->f = 0;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) + (right & 15) > 15) r->f |= PORT_FLAG_H;
	if (wide > 255) r->f |= PORT_FLAG_C;
}

static void
print_bit(struct cpu_register_state *r, port_u8 bit, port_u8 value)
{
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((value & (1u << bit)) == 0) r->f |= PORT_FLAG_Z;
}

static void
print_write(struct print_number_state *s, port_u8 value)
{
	if (s->record_writes && s->write_count < 7u) {
		port_u8 index = s->write_count;

		s->write_trace_values[index] = value;
		s->write_trace_h[index] = s->registers.h;
		s->write_trace_l[index] = s->registers.l;
		s->write_count++;
	}
	s->written = value; s->did_write = 1;
	s->write_h = s->registers.h; s->write_l = s->registers.l;
}

/* Returns the first decimal place: 2=tens through 7=millions. */
__attribute__((noinline, used)) port_u8
port_print_number_begin(struct print_number_state *s)
{
	struct cpu_register_state *r = &s->registers;
	s->saved_b = r->b; s->saved_c = r->c;
	r->a = 0; r->f = PORT_FLAG_Z;
	s->past_leading_zeroes = r->a; s->number[0] = r->a; s->number[1] = r->a;
	r->a = r->b; print_and(r, 15); print_cp(r, 1);
	if (r->f & PORT_FLAG_Z) {
		r->a = s->source[0]; s->number[2] = r->a;
	} else {
		print_cp(r, 2);
		if (r->f & PORT_FLAG_Z) {
			r->a = s->source[0]; s->number[1] = r->a;
			{ port_u16 de = (port_u16)(print_pair(r->d, r->e) + 1); r->d = (port_u8)(de >> 8); r->e = (port_u8)de; }
			r->a = s->source[1]; s->number[2] = r->a;
		} else {
			r->a = s->source[0]; s->number[0] = r->a;
			{ port_u16 de = (port_u16)(print_pair(r->d, r->e) + 1); r->d = (port_u8)(de >> 8); r->e = (port_u8)de; }
			r->a = s->source[1]; s->number[1] = r->a;
			{ port_u16 de = (port_u16)(print_pair(r->d, r->e) + 1); r->d = (port_u8)(de >> 8); r->e = (port_u8)de; }
			r->a = s->source[2]; s->number[2] = r->a;
		}
	}
	s->saved_d = r->d; s->saved_e = r->e;
	r->d = s->saved_b; r->a = r->c; r->b = r->a;
	r->a = 0; r->f = PORT_FLAG_Z; r->c = r->a; r->a = r->b;
	print_cp(r, 2); if (r->f & PORT_FLAG_Z) return 2;
	print_cp(r, 3); if (r->f & PORT_FLAG_Z) return 3;
	print_cp(r, 4); if (r->f & PORT_FLAG_Z) return 4;
	print_cp(r, 5); if (r->f & PORT_FLAG_Z) return 5;
	print_cp(r, 6); if (r->f & PORT_FLAG_Z) return 6;
	return 7;
}

static void
print_set_power(struct print_number_state *s, port_u8 a, port_u8 b, port_u8 c,
	port_u8 first_xor, port_u8 second_xor)
{
	if (first_xor) { s->registers.a = 0; s->registers.f = PORT_FLAG_Z; }
	s->registers.a = a; s->power[0] = s->registers.a;
	if (second_xor) { s->registers.a = 0; s->registers.f = PORT_FLAG_Z; }
	s->registers.a = b; s->power[1] = s->registers.a;
	s->registers.a = c; s->power[2] = s->registers.a;
}

__attribute__((noinline, used)) void port_print_number_power_millions(struct print_number_state *s) { print_set_power(s,0x0f,0x42,0x40,0,0); }
__attribute__((noinline, used)) void port_print_number_power_hundred_thousands(struct print_number_state *s) { print_set_power(s,0x01,0x86,0xa0,0,0); }
__attribute__((noinline, used)) void port_print_number_power_ten_thousands(struct print_number_state *s) { print_set_power(s,0x00,0x27,0x10,1,0); }
__attribute__((noinline, used)) void port_print_number_power_thousands(struct print_number_state *s) { print_set_power(s,0x00,0x03,0xe8,1,0); }
__attribute__((noinline, used)) void port_print_number_power_hundreds(struct print_number_state *s) { print_set_power(s,0x00,0x00,0x64,1,1); }

__attribute__((noinline, used)) void
port_print_number_tens_begin(struct print_number_state *s)
{
	s->registers.c = 0; s->registers.a = s->number[2];
}

__attribute__((noinline, used)) void
port_print_number_digit_begin(struct print_number_state *s)
{
	s->registers.c = 0;
}

static void
print_leading_zero(struct print_number_state *s)
{
	print_bit(&s->registers, 7, s->registers.d);
	if ((s->registers.f & PORT_FLAG_Z) == 0) print_write(s, 0xf6);
}

/* One pass through PrintNumber.loop. Returns 1 after a subtraction. */
__attribute__((noinline, used)) port_u8
port_print_number_digit_step(struct print_number_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = s->power[0]; r->b = r->a;
	r->a = s->number[0]; s->saved_number[0] = r->a; print_cp(r, r->b);
	if (r->f & PORT_FLAG_C) goto underflow0;
	print_sub(r, r->b); s->number[0] = r->a;

	r->a = s->power[1]; r->b = r->a;
	r->a = s->number[1]; s->saved_number[1] = r->a; print_cp(r, r->b);
	if (r->f & PORT_FLAG_C) {
		r->a = s->number[0]; print_or(r, 0);
		if (r->f & PORT_FLAG_Z) goto underflow1;
		print_dec(r, &r->a); s->number[0] = r->a; r->a = s->number[1];
	}
	print_sub(r, r->b); s->number[1] = r->a;

	r->a = s->power[2]; r->b = r->a;
	r->a = s->number[2]; s->saved_number[2] = r->a; print_cp(r, r->b);
	if (r->f & PORT_FLAG_C) {
		r->a = s->number[1]; print_and(r, r->a);
		if ((r->f & PORT_FLAG_Z) == 0) goto borrowed;
		r->a = s->number[0]; print_and(r, r->a);
		if (r->f & PORT_FLAG_Z) goto underflow2;
		print_dec(r, &r->a); s->number[0] = r->a;
		r->a = 0; r->f = PORT_FLAG_Z;
borrowed:
		print_dec(r, &r->a); s->number[1] = r->a; r->a = s->number[2];
	}
	print_sub(r, r->b); s->number[2] = r->a;
	print_inc(r, &r->c);
	return 1;

underflow2:
	r->a = s->saved_number[1]; s->number[1] = r->a;
underflow1:
	r->a = s->saved_number[0]; s->number[0] = r->a;
underflow0:
	r->a = s->past_leading_zeroes; print_or(r, r->c);
	if (r->f & PORT_FLAG_Z) print_leading_zero(s);
	else {
		r->a = 0xf6; print_add(r, r->c); print_write(s, r->a);
		s->past_leading_zeroes = r->a;
	}
	return 0;
}

__attribute__((noinline, used)) void
port_print_number_next_digit(struct print_number_state *s)
{
	struct cpu_register_state *r = &s->registers;
	print_bit(r, 7, r->d);
	if ((r->f & PORT_FLAG_Z) == 0) goto increment;
	print_bit(r, 6, r->d);
	if ((r->f & PORT_FLAG_Z) == 0) {
		r->a = s->past_leading_zeroes; print_and(r, r->a);
		if (r->f & PORT_FLAG_Z) return;
	}
increment:
	print_set_hl(r, (port_u16)(print_pair(r->h, r->l) + 1));
}

/* One pass through the repeated low-byte division by ten. */
__attribute__((noinline, used)) port_u8
port_print_number_tens_step(struct print_number_state *s)
{
	print_cp(&s->registers, 10);
	if (s->registers.f & PORT_FLAG_C) return 0;
	print_sub(&s->registers, 10); print_inc(&s->registers, &s->registers.c);
	return 1;
}

/* The .ok-to-.next transition, before NextDigit is called. */
__attribute__((noinline, used)) void
port_print_number_tens_finish(struct print_number_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->b = r->a; r->a = s->past_leading_zeroes; print_or(r, r->c);
	s->past_leading_zeroes = r->a;
	if (r->f & PORT_FLAG_Z) print_leading_zero(s);
	else { r->a = 0xf6; print_add(r, r->c); print_write(s, r->a); }
}

__attribute__((noinline, used)) void
port_print_number_ones_finish(struct print_number_state *s)
{
	struct cpu_register_state *r = &s->registers;
	r->a = 0xf6; print_add(r, r->b); print_write(s, r->a);
	print_set_hl(r, (port_u16)(print_pair(r->h, r->l) + 1));
	r->d = s->saved_d; r->e = s->saved_e;
	{ port_u16 de = (port_u16)(print_pair(r->d, r->e) - 1); r->d = (port_u8)(de >> 8); r->e = (port_u8)de; }
	r->b = s->saved_b; r->c = s->saved_c;
}

__attribute__((noinline, used)) void
port_print_number(struct print_number_state *s)
{
	s->record_writes = 1;
	s->write_count = 0;
	port_u8 place = port_print_number_begin(s);
	for (; place >= 3; place--) {
		if (place == 7) port_print_number_power_millions(s);
		else if (place == 6) port_print_number_power_hundred_thousands(s);
		else if (place == 5) port_print_number_power_ten_thousands(s);
		else if (place == 4) port_print_number_power_thousands(s);
		else port_print_number_power_hundreds(s);
		port_print_number_digit_begin(s);
		while (port_print_number_digit_step(s)) { }
		port_print_number_next_digit(s);
	}
	port_print_number_tens_begin(s);
	while (port_print_number_tens_step(s)) { }
	port_print_number_tens_finish(s);
	port_print_number_next_digit(s);
	port_print_number_ones_finish(s);
}
