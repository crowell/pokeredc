#include "port_state.h"

static port_u16
party_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
party_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8); r->l = (port_u8)value;
}

static void
party_set_de(struct cpu_register_state *r, port_u16 value)
{
	r->d = (port_u8)(value >> 8); r->e = (port_u8)value;
}

static void
party_set_bc(struct cpu_register_state *r, port_u16 value)
{
	r->b = (port_u8)(value >> 8); r->c = (port_u8)value;
}

static void
party_and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H | (r->a == 0 ? PORT_FLAG_Z : 0);
}

static void
party_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
party_inc_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->a++;
	r->f = carry;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 15) r->f |= PORT_FLAG_H;
}

static void
party_dec(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = r->f & PORT_FLAG_C;
	(*value)--;
	r->f = carry | PORT_FLAG_N;
	if (*value == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
party_add_a(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	unsigned int wide = (unsigned int)left + right;
	r->a = (port_u8)wide; r->f = 0;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) + (right & 15) > 15) r->f |= PORT_FLAG_H;
	if (wide > 0xff) r->f |= PORT_FLAG_C;
}

static void
party_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = party_pair(r->h, r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	party_set_hl(r, (port_u16)wide); r->f = flags;
}

__attribute__((noinline, used)) void
port_animate_party_mon_setup(struct animate_party_mon_state *s)
{
	party_set_hl(&s->registers, 0xcf1f);
	s->registers.a = s->current_menu_item;
	s->registers.c = s->registers.a; s->registers.b = 0;
	party_add_hl(&s->registers, party_pair(s->registers.b, s->registers.c));
	s->registers.a = s->hp_color; s->registers.c = s->registers.a;
	party_set_hl(&s->registers, 0x5769);
	party_add_hl(&s->registers, party_pair(s->registers.b, s->registers.c));
	s->registers.a = s->on_sgb;
	s->registers.a ^= 1;
	s->registers.f = s->registers.a == 0 ? PORT_FLAG_Z : 0;
	party_add_a(&s->registers, s->speed_value);
	s->registers.c = s->registers.a;
	party_add_a(&s->registers, s->registers.a);
	s->registers.b = s->registers.a;
}

/* 0 advances the timer, 1 resets OAM, and 2 edits the selected icon. */
__attribute__((noinline, used)) port_u8
port_animate_party_mon_select(struct animate_party_mon_state *s)
{
	s->registers.a = s->anim_counter;
	party_and_a(&s->registers);
	if (s->registers.a == 0) return 1;
	party_cp(&s->registers, s->registers.c);
	if ((s->registers.f & PORT_FLAG_Z) != 0) return 2;
	return 0;
}

__attribute__((noinline, used)) void
port_animate_party_mon_advance(struct animate_party_mon_state *s)
{
	party_inc_a(&s->registers);
	party_cp(&s->registers, s->registers.b);
	if ((s->registers.f & PORT_FLAG_Z) != 0) {
		s->registers.a = 0; s->registers.f = PORT_FLAG_Z;
	}
	s->anim_counter = s->registers.a;
	s->delay_dispatched = 1;
}

__attribute__((noinline, used)) void
port_animate_party_mon_reset_begin(struct animate_party_mon_state *s)
{
	s->saved_b = s->registers.b; s->saved_c = s->registers.c;
	party_set_hl(&s->registers, 0xcc5b);
	party_set_de(&s->registers, 0xc300);
	party_set_bc(&s->registers, 0x0060);
}

/* One iteration of the independently proved CopyData recurrence. */
__attribute__((noinline, used)) port_u8
port_animate_party_mon_reset_copy_step(struct animate_party_mon_state *s)
{
	port_u16 hl = (port_u16)(party_pair(s->registers.h, s->registers.l) + 1);
	port_u16 de = party_pair(s->registers.d, s->registers.e);
	port_u16 bc = (port_u16)(party_pair(s->registers.b, s->registers.c) - 1);
	s->registers.a = s->fetched;
	s->written = s->registers.a; s->write_h = s->registers.d; s->write_l = s->registers.e;
	de++;
	party_set_hl(&s->registers, hl); party_set_de(&s->registers, de); party_set_bc(&s->registers, bc);
	s->registers.a = s->registers.c;
	s->registers.a |= s->registers.b;
	s->registers.f = s->registers.a == 0 ? PORT_FLAG_Z : 0;
	return s->registers.a != 0;
}

__attribute__((noinline, used)) void
port_animate_party_mon_reset_end(struct animate_party_mon_state *s)
{
	s->registers.b = s->saved_b; s->registers.c = s->saved_c;
	s->registers.a = 0; s->registers.f = PORT_FLAG_Z;
}

__attribute__((noinline, used)) void
port_animate_party_mon_edit_begin(struct animate_party_mon_state *s)
{
	s->saved_b = s->registers.b; s->saved_c = s->registers.c;
	party_set_hl(&s->registers, 0xc302);
	party_set_bc(&s->registers, 0x0010);
	s->registers.a = s->current_menu_item;
	party_and_a(&s->registers);
	while (s->registers.a != 0) {
		party_add_hl(&s->registers, party_pair(s->registers.b, s->registers.c));
		party_dec(&s->registers, &s->registers.a);
	}
	s->registers.c = 0x40;
	s->registers.a = s->fetched;
	party_cp(&s->registers, 4);
	if ((s->registers.f & PORT_FLAG_Z) != 0) goto coords;
	party_cp(&s->registers, 8);
	if ((s->registers.f & PORT_FLAG_Z) == 0) goto ready;
coords:
	party_set_hl(&s->registers, (port_u16)(party_pair(s->registers.h, s->registers.l) - 2));
	s->registers.c = 1;
ready:
	s->registers.b = 4;
	party_set_de(&s->registers, 4);
}

/* Returns 1 for another of the four OAM entries. */
__attribute__((noinline, used)) port_u8
port_animate_party_mon_edit_step(struct animate_party_mon_state *s)
{
	s->registers.a = s->fetched;
	party_add_a(&s->registers, s->registers.c);
	s->written = s->registers.a; s->write_h = s->registers.h; s->write_l = s->registers.l;
	party_add_hl(&s->registers, party_pair(s->registers.d, s->registers.e));
	party_dec(&s->registers, &s->registers.b);
	return s->registers.b != 0;
}

__attribute__((noinline, used)) void
port_animate_party_mon_edit_end(struct animate_party_mon_state *s)
{
	s->registers.b = s->saved_b; s->registers.c = s->saved_c;
	s->registers.a = s->registers.c;
}

/* Port of AnimatePartyMon in engine/gfx/mon_icons.asm. */
__attribute__((noinline, used)) void
port_animate_party_mon(struct animate_party_mon_state *s, port_u8 *memory,
	const struct cpu_register_state *delay_frame_registers)
{
	port_u8 path;
	port_u8 continuation;
	port_u16 address;
	s->hp_color = memory[(port_u16)(0xcf1f + s->current_menu_item)];
	s->speed_value = memory[(port_u16)(0x5769 + s->hp_color)];
	port_animate_party_mon_setup(s);
	path = port_animate_party_mon_select(s);
	if (path == 1) {
		port_animate_party_mon_reset_begin(s);
		do {
			address = party_pair(s->registers.h, s->registers.l); s->fetched = memory[address];
			continuation = port_animate_party_mon_reset_copy_step(s);
			memory[party_pair(s->write_h, s->write_l)] = s->written;
		} while (continuation);
		port_animate_party_mon_reset_end(s);
	} else if (path == 2) {
		address = (port_u16)(0xc302 + (port_u16)s->current_menu_item * 16);
		s->fetched = memory[address];
		port_animate_party_mon_edit_begin(s);
		do {
			address = party_pair(s->registers.h, s->registers.l); s->fetched = memory[address];
			continuation = port_animate_party_mon_edit_step(s);
			memory[party_pair(s->write_h, s->write_l)] = s->written;
		} while (continuation);
		port_animate_party_mon_edit_end(s);
	}
	port_animate_party_mon_advance(s);
	/* DelayFrame is independently proven and is the shared tail boundary. */
	s->registers = *delay_frame_registers;
}
