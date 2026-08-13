#include "port_state.h"

static port_u16
cursor_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
cursor_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8); r->l = (port_u8)value;
}

static void
cursor_and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H | (r->a == 0 ? PORT_FLAG_Z : 0);
}

static void
cursor_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
cursor_dec_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->a--;
	r->f = carry | PORT_FLAG_N;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
cursor_add_hl(struct cpu_register_state *r)
{
	port_u16 left = cursor_pair(r->h, r->l);
	port_u16 right = cursor_pair(r->b, r->c);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	cursor_set_hl(r, (port_u16)wide); r->f = flags;
}

/* Returns 1 to enter the top-Y recurrence. */
__attribute__((noinline, used)) port_u8
port_place_menu_cursor_top_begin(struct place_menu_cursor_state *s)
{
	s->registers.a = s->top_y;
	cursor_and_a(&s->registers);
	if (s->registers.a == 0) return 0;
	cursor_set_hl(&s->registers, 0xc3a0);
	s->registers.b = 0; s->registers.c = 20;
	return 1;
}

/* Shared row recurrence; returns 1 to repeat. */
__attribute__((noinline, used)) port_u8
port_place_menu_cursor_row_step(struct place_menu_cursor_state *s)
{
	cursor_add_hl(&s->registers);
	cursor_dec_a(&s->registers);
	return s->registers.a != 0;
}

__attribute__((noinline, used)) void
port_place_menu_cursor_x(struct place_menu_cursor_state *s)
{
	s->registers.a = s->top_x;
	s->registers.b = 0; s->registers.c = s->registers.a;
	cursor_add_hl(&s->registers);
	s->saved_h = s->registers.h; s->saved_l = s->registers.l;
}

static port_u8
cursor_item_begin(struct place_menu_cursor_state *s, port_u8 item)
{
	s->registers.a = item;
	cursor_and_a(&s->registers);
	if (s->registers.a == 0) return 0;
	/* PUSH AF; BIT 1,A; BC=20 when set, otherwise 40; POP AF. */
	s->registers.f = (s->layout_flags & 2) ? 0 : PORT_FLAG_Z;
	s->registers.b = 0;
	s->registers.c = (s->layout_flags & 2) ? 20 : 40;
	s->registers.a = item;
	/* POP AF restores the flags produced by AND A. */
	s->registers.f = PORT_FLAG_H | (item == 0 ? PORT_FLAG_Z : 0);
	return 1;
}

__attribute__((noinline, used)) port_u8
port_place_menu_cursor_old_begin(struct place_menu_cursor_state *s)
{
	return cursor_item_begin(s, s->last_item);
}

__attribute__((noinline, used)) void
port_place_menu_cursor_old_end(struct place_menu_cursor_state *s)
{
	s->registers.a = s->fetched;
	cursor_cp(&s->registers, 0xed);
	if ((s->registers.f & PORT_FLAG_Z) != 0) {
		s->registers.a = s->tile_behind;
		s->written = s->registers.a;
		s->write_h = s->registers.h; s->write_l = s->registers.l;
	}
	s->registers.h = s->saved_h; s->registers.l = s->saved_l;
}

__attribute__((noinline, used)) port_u8
port_place_menu_cursor_current_begin(struct place_menu_cursor_state *s)
{
	return cursor_item_begin(s, s->current_item);
}

__attribute__((noinline, used)) void
port_place_menu_cursor_finish(struct place_menu_cursor_state *s)
{
	s->registers.a = s->fetched;
	cursor_cp(&s->registers, 0xed);
	if ((s->registers.f & PORT_FLAG_Z) == 0)
		s->tile_behind = s->registers.a;
	s->registers.a = 0xed;
	s->written = s->registers.a;
	s->write_h = s->registers.h; s->write_l = s->registers.l;
	s->registers.a = s->registers.l; s->cursor_low = s->registers.a;
	s->registers.a = s->registers.h; s->cursor_high = s->registers.a;
	s->registers.a = s->current_item; s->last_item = s->registers.a;
}

/* Port of PlaceMenuCursor in home/window.asm. */
__attribute__((noinline, used)) void
port_place_menu_cursor(struct place_menu_cursor_state *s, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 address;
	continuation = port_place_menu_cursor_top_begin(s);
	while (continuation) continuation = port_place_menu_cursor_row_step(s);
	port_place_menu_cursor_x(s);
	continuation = port_place_menu_cursor_old_begin(s);
	while (continuation) continuation = port_place_menu_cursor_row_step(s);
	address = cursor_pair(s->registers.h, s->registers.l); s->fetched = memory[address];
	s->written = memory[address];
	port_place_menu_cursor_old_end(s);
	if ((s->registers.f & PORT_FLAG_Z) != 0)
		memory[cursor_pair(s->write_h, s->write_l)] = s->written;
	continuation = port_place_menu_cursor_current_begin(s);
	while (continuation) continuation = port_place_menu_cursor_row_step(s);
	address = cursor_pair(s->registers.h, s->registers.l); s->fetched = memory[address];
	port_place_menu_cursor_finish(s);
	memory[cursor_pair(s->write_h, s->write_l)] = s->written;
}
