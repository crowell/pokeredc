#include "port_state.h"

static port_u16
border_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
border_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8);
	r->l = (port_u8)value;
}

static void
border_inc_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->a++;
	r->f = carry;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
border_dec(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = r->f & PORT_FLAG_C;
	(*value)--;
	r->f = carry | PORT_FLAG_N;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
border_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = border_pair(r->h, r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	border_set_hl(r, (port_u16)wide); r->f = flags;
}

static void
border_write(struct text_box_border_state *s, port_u8 value, port_u8 increment)
{
	port_u16 hl = border_pair(s->registers.h, s->registers.l);
	s->registers.a = value;
	s->written = value; s->write_h = s->registers.h; s->write_l = s->registers.l;
	if (increment) border_set_hl(&s->registers, (port_u16)(hl + 1));
}

__attribute__((noinline, used)) void
port_text_box_border_top_begin(struct text_box_border_state *s)
{
	s->saved_h = s->registers.h; s->saved_l = s->registers.l;
	border_write(s, 0x79, 1);
	border_inc_a(&s->registers);
	s->registers.d = s->registers.c;
}

/* Exact .PlaceChars iteration; returns 1 to repeat. */
__attribute__((noinline, used)) port_u8
port_text_box_border_place_char_step(struct text_box_border_state *s)
{
	port_u16 hl = border_pair(s->registers.h, s->registers.l);
	s->written = s->registers.a; s->write_h = s->registers.h; s->write_l = s->registers.l;
	border_set_hl(&s->registers, (port_u16)(hl + 1));
	border_dec(&s->registers, &s->registers.d);
	return s->registers.d != 0;
}

__attribute__((noinline, used)) void
port_text_box_border_top_end(struct text_box_border_state *s)
{
	border_inc_a(&s->registers);
	border_write(s, s->registers.a, 0);
	s->registers.h = s->saved_h; s->registers.l = s->saved_l;
	s->registers.d = 0; s->registers.e = 20;
	border_add_hl(&s->registers, 20);
}

__attribute__((noinline, used)) void
port_text_box_border_middle_begin(struct text_box_border_state *s)
{
	s->saved_h = s->registers.h; s->saved_l = s->registers.l;
	border_write(s, 0x7c, 1);
	s->registers.a = 0x7f;
	s->registers.d = s->registers.c;
}

/* Returns 1 for another middle row, or 0 for the bottom row. */
__attribute__((noinline, used)) port_u8
port_text_box_border_middle_end(struct text_box_border_state *s)
{
	s->written = 0x7c; s->write_h = s->registers.h; s->write_l = s->registers.l;
	s->registers.h = s->saved_h; s->registers.l = s->saved_l;
	s->registers.d = 0; s->registers.e = 20;
	border_add_hl(&s->registers, 20);
	border_dec(&s->registers, &s->registers.b);
	return s->registers.b != 0;
}

__attribute__((noinline, used)) void
port_text_box_border_bottom_begin(struct text_box_border_state *s)
{
	border_write(s, 0x7d, 1);
	s->registers.a = 0x7a;
	s->registers.d = s->registers.c;
}

__attribute__((noinline, used)) void
port_text_box_border_bottom_end(struct text_box_border_state *s)
{
	s->written = 0x7e; s->write_h = s->registers.h; s->write_l = s->registers.l;
}

__attribute__((noinline, used)) void
port_text_box_border(struct text_box_border_state *s, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 address;
	port_text_box_border_top_begin(s);
	address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
	do { continuation = port_text_box_border_place_char_step(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written; } while (continuation);
	port_text_box_border_top_end(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
	do {
		port_text_box_border_middle_begin(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
		do { continuation = port_text_box_border_place_char_step(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written; } while (continuation);
		continuation = port_text_box_border_middle_end(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
	} while (continuation);
	port_text_box_border_bottom_begin(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
	do { continuation = port_text_box_border_place_char_step(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written; } while (continuation);
	port_text_box_border_bottom_end(s); address = border_pair(s->write_h, s->write_l); memory[address] = s->written;
}
