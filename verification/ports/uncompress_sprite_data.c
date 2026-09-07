#include "port_state.h"
#ifdef PORT_PLATFORM_RUNTIME
#include "bank.h"
#endif

void port_fill_memory(struct fill_memory_state *, port_u8 *);
void port_read_next_input_byte(struct next_input_byte_state *);
void port_read_next_input_bit(struct cpu_register_state *, port_u8 *);
void port_write_sprite_bits_to_buffer(struct write_sprite_bits_state *);
void port_unpack_sprite(struct cpu_register_state *, port_u8 *);

static port_u16 word(const port_u8 *m, port_u16 a)
{
	return (port_u16)(m[a] | ((port_u16)m[a + 1] << 8));
}
static void put_word(port_u8 *m, port_u16 a, port_u16 value)
{
	m[a] = (port_u8)value;
	m[a + 1] = (port_u8)(value >> 8);
}
static port_u8 bit(struct cpu_register_state *r, port_u8 *m)
{
	port_read_next_input_bit(r, m);
	return r->a;
}

/* Runtime composition of _UncompressSpriteData, UncompressSpriteDataLoop
 * and MoveToNextBufferPosition in home/uncompress.asm. The assembly unwinds
 * its call stack at the end of each plane; C expresses that as a bounded
 * plane loop. Existing bit reader, bit writer and unpacking ports do the
 * actual data operations. TODO(proof): add a composed equivalence proof of
 * these loops; asset round trips alone are not an SM83 equivalence proof.
 * Returns zero for a malformed stream outside the valid 1..7 tile domain. */
__attribute__((noinline, used)) port_u8
port_uncompress_sprite_data(struct cpu_register_state *r, port_u8 *m)
{
	port_u8 saved_bank = m[0xffb8], saved_f = r->f;
	port_u8 requested_bank = r->a;
	port_u8 valid = 1;
	struct fill_memory_state fill = {0};
	struct next_input_byte_state input = {0};
#ifdef PORT_PLATFORM_RUNTIME
	if (requested_bank >= PORT_ROM_BANK_COUNT) return 0;
#endif
	m[0xffb8] = requested_bank;
	m[0x2000] = requested_bank;
#ifdef PORT_PLATFORM_RUNTIME
	port_sync_rom_window(m, requested_bank);
#endif
	/* The SRAM window is bank zero; no save data is used as scratch. */
#ifdef PORT_PLATFORM_RUNTIME
	/* MBC control writes are not writes to the ROM read window. */
	port_sram_enable(m, 1);
#else
	m[0x0000] = 0x0a;
	m[0x4000] = 0;
#endif
	fill.registers.h = 0xa1;
	fill.registers.l = 0x88;
	fill.registers.b = 3;
	fill.registers.c = 0x10;
	port_fill_memory(&fill, m);
	*r = fill.registers;
	m[0xd0a6] = 1;
	m[0xd0a7] = 3;
	m[0xd0a1] = m[0xd0a2] = m[0xd0a8] = 0;
	input.registers = *r;
	input.pointer_low = m[0xd0ab];
	input.pointer_high = m[0xd0ac];
	input.source = m[word(m, 0xd0ab)];
	port_read_next_input_byte(&input);
	*r = input.registers;
	m[0xd0ab] = input.pointer_low;
	m[0xd0ac] = input.pointer_high;
	unsigned width = r->a >> 4, height = r->a & 15;
	if (!width || !height || width > 7 || height > 7) {
		valid = 0;
		goto done;
	}
	m[0xd0a3] = (port_u8)(width * 8);
	m[0xd0a4] = (port_u8)(height * 8);
	m[0xd0a8] = bit(r, m);
	height *= 8;
	for (unsigned plane = 0; plane < 2; ++plane) {
		port_u16 buffer = (m[0xd0a8] & 1) ? 0xa310 : 0xa188;
		put_word(m, 0xd0ad, buffer);
		put_word(m, 0xd0af, buffer);
		if (plane) {
			port_u8 mode = bit(r, m);
			if (mode) mode = (port_u8)(1 + bit(r, m));
			m[0xd0a9] = mode;
		}
		unsigned zeroes = 0;
		int run = bit(r, m) == 0;
		for (unsigned group = 0; group < width * height * 4; ++group) {
			unsigned pair = 0;
			if (!zeroes && !run) {
				pair = bit(r, m) << 1;
				pair |= bit(r, m);
				run = pair == 0;
			}
			if (run) {
				unsigned ones = 0, value = 0;
				while (bit(r, m)) {
					if (++ones >= 16) { valid = 0; goto done; }
				}
				for (unsigned i = 0; i <= ones; ++i)
					value = (value << 1) | bit(r, m);
				zeroes = (1u << (ones + 1)) - 1 + value;
				run = 0;
			}
			if (zeroes) { pair = 0; --zeroes; }
			unsigned column = group / (height * 4);
			unsigned y = group % height;
			port_u16 dest = (port_u16)(buffer + column * height + y);
			struct write_sprite_bits_state write = {0};
			m[0xd0a1] = (port_u8)(column * 8);
			m[0xd0a2] = (port_u8)y;
			m[0xd0a7] = (port_u8)(3 - (group / height) % 4);
			put_word(m, 0xd0ad, dest);
			put_word(m, 0xd0af, (port_u16)(buffer + column * height));
			write.registers = *r;
			write.registers.a = (port_u8)pair;
			write.bit_offset = m[0xd0a7];
			write.pointer_low = (port_u8)dest;
			write.pointer_high = (port_u8)(dest >> 8);
			write.pointed_byte = m[dest];
			port_write_sprite_bits_to_buffer(&write);
			*r = write.registers;
			m[dest] = write.pointed_byte;
		}
		m[0xd0a1] = m[0xd0a2] = 0;
		m[0xd0a7] = 3;
		if (!plane) m[0xd0a8] = (port_u8)((m[0xd0a8] ^ 1) | 2);
	}
	port_unpack_sprite(r, m);
done:
	m[0xffb8] = saved_bank;
	m[0x2000] = saved_bank;
#ifdef PORT_PLATFORM_RUNTIME
	port_sync_rom_window(m, saved_bank);
#endif
	r->a = saved_bank;
	r->f = saved_f;
	return valid;
}
