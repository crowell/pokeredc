#include "port_state.h"

static const port_u8 pewter_data[] = {
	0x12, 0x1b, 0xfa, 0x7c, 0x10, 0x1b, 0xfd, 0x7c,
	0x11, 0x1a, 0x00, 0x7d, 0x11, 0x1c, 0x03, 0x7d,
	0x40, 0x40, 0xff, 0x10, 0x20, 0xff, 0x40, 0x10,
	0xff, 0x40, 0x20, 0xff, 0x10, 0x22, 0x1a, 0x7d,
	0x11, 0x23, 0x1f, 0x7d, 0x12, 0x25, 0x24, 0x7d,
	0x13, 0x25, 0x30, 0x7d, 0x11, 0x24, 0x35, 0x7d,
	0x20, 0x80, 0x80, 0x10, 0xff, 0x20, 0x80, 0x10,
	0x20, 0xff, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x20, 0x20, 0x40,
	0x20, 0xff, 0x20, 0x80, 0x20, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff,
};

static port_u16
pewter_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
pewter_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
pewter_inc_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->a++;
	r->f = carry;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
pewter_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = pewter_pair(r->h, r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	r->h = (port_u8)(wide >> 8); r->l = (port_u8)wide; r->f = flags;
}

__attribute__((noinline, used)) void
port_pewter_guys_setup(struct pewter_guys_state *s)
{
	port_u16 destination;
	port_u8 old;
	s->registers.h = 0xcc; s->registers.l = 0xd3;
	s->registers.a = s->joypad_index;
	old = s->registers.a; s->registers.a--;
	s->registers.f = (s->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (s->registers.a == 0) s->registers.f |= PORT_FLAG_Z;
	if ((old & 15) == 0) s->registers.f |= PORT_FLAG_H;
	s->joypad_index = s->registers.a;
	s->registers.d = 0; s->registers.e = s->registers.a;
	pewter_add_hl(&s->registers, s->registers.e);
	s->registers.d = s->registers.h; s->registers.e = s->registers.l;
	s->registers.h = 0x7c; s->registers.l = 0xe6;
	s->registers.a = s->which_guy;
	old = s->registers.a;
	s->registers.a = (port_u8)(old + old); s->registers.f = 0;
	if (s->registers.a == 0) s->registers.f |= PORT_FLAG_Z;
	if ((old & 15) + (old & 15) > 15) s->registers.f |= PORT_FLAG_H;
	if ((unsigned int)old + old > 0xff) s->registers.f |= PORT_FLAG_C;
	s->registers.b = 0; s->registers.c = s->registers.a;
	pewter_add_hl(&s->registers, s->registers.c);
	destination = s->which_guy == 0 ? 0x7cea : 0x7d06;
	s->registers.a = (port_u8)destination;
	s->registers.h = (port_u8)(destination >> 8); s->registers.l = s->registers.a;
	s->registers.a = s->y_coord; s->registers.b = s->registers.a;
	s->registers.a = s->x_coord; s->registers.c = s->registers.a;
}

/* Returns 1 on a coordinate match and 0 for the next four-byte entry. */
__attribute__((noinline, used)) port_u8
port_pewter_guys_scan_step(struct pewter_guys_state *s)
{
	port_u16 hl = pewter_pair(s->registers.h, s->registers.l);
	s->registers.a = s->entry_y; hl++; pewter_cp(&s->registers, s->registers.b);
	if ((s->registers.f & PORT_FLAG_Z) == 0) { hl += 3; goto repeat; }
	s->registers.a = s->entry_x; hl++; pewter_cp(&s->registers, s->registers.c);
	if ((s->registers.f & PORT_FLAG_Z) == 0) { hl += 2; goto repeat; }
	s->registers.a = s->entry_low; hl++;
	s->registers.h = s->entry_high; s->registers.l = s->registers.a;
	return 1;
repeat:
	s->registers.h = (port_u8)(hl >> 8); s->registers.l = (port_u8)hl;
	return 0;
}

/* Returns 1 after copying a byte, or 0 at the ff terminator. */
__attribute__((noinline, used)) port_u8
port_pewter_guys_copy_step(struct pewter_guys_state *s)
{
	port_u16 hl = (port_u16)(pewter_pair(s->registers.h, s->registers.l) + 1);
	port_u16 de;
	s->registers.a = s->movement; pewter_cp(&s->registers, 0xff);
	s->registers.h = (port_u8)(hl >> 8); s->registers.l = (port_u8)hl;
	if (s->movement == 0xff) return 0;
	de = pewter_pair(s->registers.d, s->registers.e);
	s->written = s->registers.a; s->write_h = s->registers.d; s->write_l = s->registers.e;
	de++; s->registers.d = (port_u8)(de >> 8); s->registers.e = (port_u8)de;
	s->registers.a = s->joypad_index; pewter_inc_a(&s->registers); s->joypad_index = s->registers.a;
	return 1;
}

static port_u8
pewter_read(port_u16 address)
{
	return pewter_data[(port_u16)(address - 0x7cea)];
}

__attribute__((noinline, used)) void
port_pewter_guys(struct pewter_guys_state *s, port_u8 *memory)
{
	port_u16 address;
	port_pewter_guys_setup(s);
	for (;;) {
		address = pewter_pair(s->registers.h, s->registers.l);
		s->entry_y = pewter_read(address); s->entry_x = pewter_read(address + 1);
		s->entry_low = pewter_read(address + 2); s->entry_high = pewter_read(address + 3);
		if (port_pewter_guys_scan_step(s)) break;
	}
	for (;;) {
		address = pewter_pair(s->registers.h, s->registers.l);
		s->movement = pewter_read(address);
		if (!port_pewter_guys_copy_step(s)) break;
		memory[pewter_pair(s->write_h, s->write_l)] = s->written;
	}
}
