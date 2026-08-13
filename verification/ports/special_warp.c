#include "port_state.h"

static port_u16
warp_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
warp_set_hl(struct cpu_register_state *r, port_u16 value)
{
	r->h = (port_u8)(value >> 8); r->l = (port_u8)value;
}

static void
warp_set_de(struct cpu_register_state *r, port_u16 value)
{
	r->d = (port_u8)(value >> 8); r->e = (port_u8)value;
}

static void
warp_cp(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right) r->f |= PORT_FLAG_Z;
	if ((left & 15) < (right & 15)) r->f |= PORT_FLAG_H;
	if (left < right) r->f |= PORT_FLAG_C;
}

static void
warp_dec_c(struct cpu_register_state *r)
{
	port_u8 old = r->c;
	port_u8 carry = r->f & PORT_FLAG_C;
	r->c--;
	r->f = carry | PORT_FLAG_N;
	if (r->c == 0) r->f |= PORT_FLAG_Z;
	if ((old & 15) == 0) r->f |= PORT_FLAG_H;
}

static void
warp_add_a(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	unsigned int wide = (unsigned int)left + right;
	r->a = (port_u8)wide; r->f = 0;
	if (r->a == 0) r->f |= PORT_FLAG_Z;
	if ((left & 15) + (right & 15) > 15) r->f |= PORT_FLAG_H;
	if (wide > 0xff) r->f |= PORT_FLAG_C;
}

static void
warp_add_hl(struct cpu_register_state *r, port_u16 right)
{
	port_u16 left = warp_pair(r->h, r->l);
	unsigned long wide = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;
	if ((left & 0xfff) + (right & 0xfff) > 0xfff) flags |= PORT_FLAG_H;
	if (wide > 0xffff) flags |= PORT_FLAG_C;
	warp_set_hl(r, (port_u16)wide); r->f = flags;
}

static const port_u8 dungeon_warp_list[] = {
	0x9f, 1, 0x9f, 2, 0xa0, 1, 0xa0, 2,
	0xa1, 1, 0xa1, 2, 0xa2, 1, 0xa2, 2,
	0xc2, 2, 0xa5, 1, 0xa5, 2, 0xd6, 3, 0xff,
};

static const port_u8 dungeon_warp_data[] = {
	0x46,0xc7,0x07,0x12,0x01,0x00, 0x48,0xc7,0x07,0x17,0x01,0x01,
	0x46,0xc7,0x07,0x13,0x01,0x01, 0x48,0xc7,0x07,0x16,0x01,0x00,
	0x46,0xc7,0x07,0x12,0x01,0x00, 0x46,0xc7,0x07,0x13,0x01,0x01,
	0x93,0xc7,0x0e,0x04,0x00,0x00, 0x93,0xc7,0x0e,0x05,0x00,0x01,
	0xb1,0xc7,0x10,0x16,0x00,0x00, 0x99,0xc7,0x0e,0x10,0x00,0x00,
	0x99,0xc7,0x0e,0x10,0x00,0x00, 0x9a,0xc7,0x0e,0x12,0x00,0x00,
};

static const port_u8 fixed_warp_data[] = {
	0x26,0x12,0xc7,0x06,0x03,0x00,0x01,0x04,
	0xef,0x0b,0xc7,0x04,0x03,0x00,0x01,0x15,
	0xef,0x0d,0xc7,0x04,0x06,0x00,0x00,0x15,
	0xf0,0x0b,0xc7,0x04,0x03,0x00,0x01,0x15,
	0xf0,0x0d,0xc7,0x04,0x06,0x00,0x00,0x15,
};

static const port_u8 fly_warp_data[] = {
	0x00,0x00,0x7c,0x64, 0x01,0x00,0x82,0x64, 0x02,0x00,0x88,0x64,
	0x03,0x00,0x8e,0x64, 0x04,0x00,0x94,0x64, 0x05,0x00,0x9a,0x64,
	0x06,0x00,0xa0,0x64, 0x07,0x00,0xa6,0x64, 0x08,0x00,0xac,0x64,
	0x09,0x00,0xb2,0x64, 0x0a,0x00,0xb8,0x64, 0x0f,0x00,0xbe,0x64,
	0x15,0x00,0xc4,0x64,
	0x2b,0xc7,0x06,0x05,0x00,0x01, 0x60,0xc8,0x1a,0x17,0x00,0x01,
	0x5b,0xc8,0x1a,0x0d,0x00,0x01, 0xf6,0xc7,0x12,0x13,0x00,0x01,
	0x2a,0xc7,0x06,0x03,0x00,0x01, 0x3c,0xc7,0x04,0x0b,0x00,0x01,
	0xb7,0xc7,0x0a,0x29,0x00,0x01, 0x78,0xc8,0x1c,0x13,0x00,0x01,
	0x5e,0xc7,0x0c,0x0b,0x00,0x01, 0x2d,0xc7,0x06,0x09,0x00,0x01,
	0x8d,0xc8,0x1e,0x09,0x00,0x01, 0xba,0xc7,0x06,0x0b,0x00,0x01,
	0x9e,0xc7,0x14,0x0b,0x00,0x01,
};

static port_u8
warp_rom_read(port_u16 address)
{
	if (address >= 0x63bf && address < 0x63d8)
		return dungeon_warp_list[address - 0x63bf];
	if (address >= 0x63d8 && address < 0x6420)
		return dungeon_warp_data[address - 0x63d8];
	if (address >= 0x6420 && address < 0x6448)
		return fixed_warp_data[address - 0x6420];
	return fly_warp_data[address - 0x6448];
}

/* Returns: 0 generic warp routing, 1 copy a fixed eight-byte cable/new-game spec. */
__attribute__((noinline, used)) port_u8
port_load_special_warp_select_fixed(struct special_warp_state *s)
{
	s->registers.a = s->cable_destination;
	warp_cp(&s->registers, 0xef);
	if (s->cable_destination == 0xef) {
		warp_set_hl(&s->registers, 0x6428);
		s->registers.a = s->serial_status;
		warp_cp(&s->registers, 2);
		if (s->serial_status != 2) warp_set_hl(&s->registers, 0x6430);
		return 1;
	}
	warp_cp(&s->registers, 0xf0);
	if (s->cable_destination == 0xf0) {
		warp_set_hl(&s->registers, 0x6438);
		s->registers.a = s->serial_status;
		warp_cp(&s->registers, 2);
		if (s->serial_status != 2) warp_set_hl(&s->registers, 0x6440);
		return 1;
	}
	s->registers.a = s->status6;
	/* Debug mode (bit 1) or fly/dungeon warp (bit 2) uses generic routing. */
	s->registers.f = (s->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((s->registers.a & 2) == 0) s->registers.f |= PORT_FLAG_Z;
	if (s->registers.a & 2) return 0;
	s->registers.f = (s->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((s->registers.a & 4) == 0) s->registers.f |= PORT_FLAG_Z;
	if (s->registers.a & 4) return 0;
	warp_set_hl(&s->registers, 0x6420);
	return 1;
}

__attribute__((noinline, used)) void
port_load_special_warp_fixed_begin(struct special_warp_state *s)
{
	warp_set_de(&s->registers, 0xd35e);
	s->registers.c = 7;
}

/* Fixed and generic copies share this exact HLI/DE/C transition. */
__attribute__((noinline, used)) port_u8
port_load_special_warp_copy_step(struct special_warp_state *s)
{
	port_u16 hl = (port_u16)(warp_pair(s->registers.h, s->registers.l) + 1);
	port_u16 de = warp_pair(s->registers.d, s->registers.e);
	s->registers.a = s->fetched0;
	s->written = s->registers.a; s->write_h = s->registers.d; s->write_l = s->registers.e;
	de++;
	warp_set_hl(&s->registers, hl); warp_set_de(&s->registers, de);
	warp_dec_c(&s->registers);
	return s->registers.c != 0;
}

__attribute__((noinline, used)) void
port_load_special_warp_fixed_end(struct special_warp_state *s)
{
	port_u16 hl = (port_u16)(warp_pair(s->registers.h, s->registers.l) + 1);
	s->registers.a = s->fetched0;
	s->current_tileset = s->registers.a;
	warp_set_hl(&s->registers, hl);
	s->registers.a = 0; s->registers.f = PORT_FLAG_Z;
}

/* Returns 1 for dungeon-warp routing, 0 for fly/escape/ordinary routing. */
__attribute__((noinline, used)) port_u8
port_load_special_warp_route_kind(struct special_warp_state *s)
{
	port_u8 escape;
	s->registers.a = s->last_map;
	warp_set_hl(&s->registers, 0xd732);
	/* BIT 4,[status6]. */
	s->registers.f = (s->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((s->status6 & 0x10) == 0) s->registers.f |= PORT_FLAG_Z;
	if (s->status6 & 0x10) return 1;
	/* BIT/RES 6: RES preserves the BIT flags. */
	escape = s->status6 & 0x40;
	s->registers.f = (s->registers.f & PORT_FLAG_C) | PORT_FLAG_H;
	if (escape == 0) s->registers.f |= PORT_FLAG_Z;
	s->status6 &= 0xbf;
	if (escape) s->registers.a = s->last_blackout_map;
	else s->registers.a = s->destination_map;
	s->registers.b = s->registers.a;
	s->current_map = s->registers.a;
	warp_set_hl(&s->registers, 0x6448);
	return 0;
}

__attribute__((noinline, used)) void
port_load_special_warp_dungeon_begin(struct special_warp_state *s)
{
	s->status3 &= 0xef;
	s->registers.a = s->dungeon_destination;
	s->registers.b = s->registers.a; s->current_map = s->registers.a;
	s->registers.a = s->which_dungeon_warp; s->registers.c = s->registers.a;
	warp_set_hl(&s->registers, 0x63bf); warp_set_de(&s->registers, 0);
	s->registers.a = 6; s->dungeon_entry_size = s->registers.a;
}

/* Returns 1 on destination+ID match, 0 after advancing the six-byte offset. */
__attribute__((noinline, used)) port_u8
port_load_special_warp_dungeon_scan(struct special_warp_state *s)
{
	port_u16 hl = warp_pair(s->registers.h, s->registers.l);
	s->registers.a = s->fetched0; hl++; warp_cp(&s->registers, s->registers.b);
	if ((s->registers.f & PORT_FLAG_Z) != 0) {
		s->registers.a = s->fetched1; hl++; warp_cp(&s->registers, s->registers.c);
		if ((s->registers.f & PORT_FLAG_Z) != 0) { warp_set_hl(&s->registers, hl); return 1; }
	} else hl++;
	s->registers.a = s->dungeon_entry_size;
	warp_add_a(&s->registers, s->registers.e);
	s->registers.e = s->registers.a;
	warp_set_hl(&s->registers, hl);
	return 0;
}

__attribute__((noinline, used)) void
port_load_special_warp_dungeon_found(struct special_warp_state *s)
{
	warp_set_hl(&s->registers, 0x63d8);
	warp_add_hl(&s->registers, warp_pair(s->registers.d, s->registers.e));
}

/* Returns 1 when the map ID matches, otherwise advances four table bytes. */
__attribute__((noinline, used)) port_u8
port_load_special_warp_fly_scan(struct special_warp_state *s)
{
	port_u16 hl = (port_u16)(warp_pair(s->registers.h, s->registers.l) + 2);
	s->registers.a = s->fetched0;
	warp_cp(&s->registers, s->registers.b);
	if ((s->registers.f & PORT_FLAG_Z) != 0) { warp_set_hl(&s->registers, hl); return 1; }
	hl += 2; warp_set_hl(&s->registers, hl); return 0;
}

__attribute__((noinline, used)) void
port_load_special_warp_fly_found(struct special_warp_state *s)
{
	s->registers.a = s->fetched0;
	s->registers.h = s->fetched1; s->registers.l = s->registers.a;
}

__attribute__((noinline, used)) void
port_load_special_warp_generic_copy_begin(struct special_warp_state *s)
{
	warp_set_de(&s->registers, 0xd35f); s->registers.c = 6;
}

__attribute__((noinline, used)) void
port_load_special_warp_generic_end(struct special_warp_state *s)
{
	s->registers.a = 0; s->registers.f = PORT_FLAG_Z; s->current_tileset = 0;
}

__attribute__((noinline, used)) void
port_load_special_warp_finish(struct special_warp_state *s)
{
	s->y_offset = s->registers.a; s->x_offset = s->registers.a;
	s->registers.a = 0xff; s->destination_warp_id = s->registers.a;
}

/* Port of LoadSpecialWarpData in engine/overworld/special_warps.asm. */
__attribute__((noinline, used)) void
port_load_special_warp_data(struct special_warp_state *s, port_u8 *memory)
{
	port_u8 continuation;
	port_u16 address;
	if (port_load_special_warp_select_fixed(s)) {
		port_load_special_warp_fixed_begin(s);
		do {
			s->fetched0 = warp_rom_read(warp_pair(s->registers.h,
				s->registers.l));
			continuation = port_load_special_warp_copy_step(s);
			address = warp_pair(s->write_h, s->write_l);
			memory[address] = s->written;
			if (address == 0xd35e) s->current_map = s->written;
		} while (continuation);
		s->fetched0 = warp_rom_read(warp_pair(s->registers.h,
			s->registers.l));
		port_load_special_warp_fixed_end(s);
	} else {
		if (port_load_special_warp_route_kind(s)) {
			port_load_special_warp_dungeon_begin(s);
			do {
				address = warp_pair(s->registers.h, s->registers.l);
				s->fetched0 = warp_rom_read(address);
				s->fetched1 = warp_rom_read((port_u16)(address + 1));
				continuation = port_load_special_warp_dungeon_scan(s);
			} while (!continuation);
			port_load_special_warp_dungeon_found(s);
		} else {
			do {
				address = warp_pair(s->registers.h, s->registers.l);
				s->fetched0 = warp_rom_read(address);
				continuation = port_load_special_warp_fly_scan(s);
			} while (!continuation);
			address = warp_pair(s->registers.h, s->registers.l);
			s->fetched0 = warp_rom_read(address);
			s->fetched1 = warp_rom_read((port_u16)(address + 1));
			port_load_special_warp_fly_found(s);
		}
		port_load_special_warp_generic_copy_begin(s);
		do {
			s->fetched0 = warp_rom_read(warp_pair(s->registers.h,
				s->registers.l));
			continuation = port_load_special_warp_copy_step(s);
			memory[warp_pair(s->write_h, s->write_l)] = s->written;
		} while (continuation);
		port_load_special_warp_generic_end(s);
	}
	port_load_special_warp_finish(s);
}
