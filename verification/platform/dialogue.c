#include "platform.h"
#include <stdio.h>
#include <string.h>

void port_place_string_resume(struct place_string_resume_state *, port_u8 *);
void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_get_cry_data(struct cpu_register_state *, port_u8 *);
void port_text_command_ram(struct cpu_register_state *, port_u8 *);
void port_text_command_bcd(struct cpu_register_state *, port_u8 *);
void port_text_command_move(struct cpu_register_state *, port_u8 *);

static void text_finish(struct mac_text *t, uint8_t *m)
{
	t->active = 0;
	m[0xd358] = t->saved_flags;
	m[0xc4f2] = 0x7f;
}

void text_begin(struct mac_text *t, uint8_t *m, unsigned bank, unsigned pointer)
{
	memset(t, 0, sizeof(*t));
	t->active = 1;
	t->bank = bank;
	t->pointer = pointer;
	t->destination = W_TILE_MAP + 14 * 20 + 1;
	t->saved_flags = m[0xd358];
	m[0xd358] = (m[0xd358] | 2) ^ m[0xfff4];
	for (unsigned y = 13; y <= 16; ++y)
		memset(m + W_TILE_MAP + y * 20 + 1, 0x7f, 18);
	struct text_box_border_state box = {0};
	box.registers.h = 0xc4;
	box.registers.l = 0x90;
	box.registers.b = 4;
	box.registers.c = 18;
	port_text_box_border(&box, m);
	t->delay = 3; /* PrintText's initial tilemap transfer. */
}

static unsigned read_byte(struct mac_text *t, const uint8_t *m)
{
	if (t->pointer < 0x4000 || t->pointer >= 0x8000)
		return m[t->pointer++ & 0xffff];
	return m[PORT_ROM_BACKING_BASE + t->bank * 0x4000 + t->pointer++ - 0x4000];
}

static void start_string(struct mac_text *t, unsigned pointer)
{
	memset(&t->string, 0, sizeof(t->string));
	t->string.saved_cursor = (port_u16)t->destination;
	t->string.registers.h = (port_u8)(t->destination >> 8);
	t->string.registers.l = (port_u8)t->destination;
	t->string.registers.d = (port_u8)(pointer >> 8);
	t->string.registers.e = (port_u8)pointer;
	t->in_string = 1;
}

/* NextTextCommand/PlaceNextChar continuations. The host supplies real frame
 * and button observations instead of auto-acknowledging every wait. These
 * supported commands cover Oak's original ROM streams; TODO(text-complete):
 * implement the remaining commands, including number/ASM dispatch, and
 * prove this resumable composition. Unsupported commands report and stop;
 * they must not silently skip game logic or execute SM83 instructions. */
void text_tick(struct mac_text *t, uint8_t *m, uint8_t pressed, uint8_t held)
{
	if (!t->active) return;
	if (t->delay) { --t->delay; return; }
	if (t->sound_wait) {
		if (m[0xc02a] || m[0xc02b] || m[0xc02d]) return;
		t->sound_wait = 0;
	}
	/* Bounded command processing catches invalid streams without hanging
	 * the application. Normal text yields after a single character. */
	for (unsigned commands = 0; commands < 32; ++commands) {
		if (t->in_string) {
			unsigned saved_bank = m[H_LOADED_ROM_BANK];
			port_sync_rom_window(m, (port_u8)t->bank);
			m[H_LOADED_ROM_BANK] = (port_u8)t->bank;
			t->string.acknowledge = (pressed & (PAD_A | PAD_B)) != 0;
			port_place_string_resume(&t->string, m);
			m[H_LOADED_ROM_BANK] = (port_u8)saved_bank;
			port_sync_rom_window(m, (port_u8)saved_bank);
			if (t->string.waiting) return;
			if (t->string.done) {
				if (t->string.token != 0x50) { text_finish(t, m); return; }
				t->destination = t->string.registers.b * 256u + t->string.registers.c;
				t->pointer = t->string.registers.d * 256u + t->string.registers.e + 1;
				t->in_string = 0;
				continue;
			}
			unsigned token = t->string.token;
			/* The leaf handlers currently execute both scroll copies in one
			 * call. Preserve the wait duration here; TODO: expose the midpoint
			 * for the original five-frame first-row animation. */
			if (token == 0x51 || token == 0x49) t->delay = 19;
			else if (token == 0x55 || token == 0x4b || token == 0x4c) t->delay = 9;
			else if (token >= 0x60 || (token >= 0x52 && token <= 0x5e)) {
				unsigned frames = (held & (PAD_A | PAD_B)) ? 1 :
					(m[0xd358] & 1) ? m[0xd355] & 15 : 1;
				t->delay = frames ? frames - 1 : 0;
			} else continue;
			return;
		}
		unsigned command = read_byte(t, m);
		if (command == 0x50) {
			if (!t->depth) { text_finish(t, m); return; }
			--t->depth;
			t->pointer = t->return_pointer[t->depth];
			t->bank = t->return_bank[t->depth];
		} else if (command == 0x17) {
			unsigned lo = read_byte(t, m), hi = read_byte(t, m);
			unsigned bank = read_byte(t, m);
			if (bank >= PORT_ROM_BANK_COUNT || t->depth >= 8) break;
			t->return_pointer[t->depth] = t->pointer;
			t->return_bank[t->depth++] = t->bank;
			t->pointer = lo + hi * 256;
			t->bank = bank;
		} else if (command == 0) {
			start_string(t, t->pointer);
		} else if (command == 0x01) {
			/* TextCommand_RAM reads its two-byte source operand from the
			 * current ROM stream, renders that RAM string, and returns HL at
			 * the following command with BC at the advanced cursor. */
			unsigned saved_bank = m[H_LOADED_ROM_BANK];
			struct cpu_register_state r = {
				.b = (port_u8)(t->destination >> 8),
				.c = (port_u8)t->destination,
				.h = (port_u8)(t->pointer >> 8),
				.l = (port_u8)t->pointer,
			};
			port_sync_rom_window(m, (port_u8)t->bank);
			m[H_LOADED_ROM_BANK] = (port_u8)t->bank;
			m[R_ROMB] = (port_u8)t->bank;
			port_text_command_ram(&r, m);
			t->pointer = r.h * 256u + r.l;
			t->destination = r.b * 256u + r.c;
			m[H_LOADED_ROM_BANK] = (port_u8)saved_bank;
			m[R_ROMB] = (port_u8)saved_bank;
			port_sync_rom_window(m, (port_u8)saved_bank);
		} else if (command == 0x02) {
			/* TextCommand_BCD reads its RAM source and format operands from
			 * the banked command stream and returns the two live cursors. */
			unsigned saved_bank = m[H_LOADED_ROM_BANK];
			struct cpu_register_state r = {
				.b = (port_u8)(t->destination >> 8),
				.c = (port_u8)t->destination,
				.h = (port_u8)(t->pointer >> 8),
				.l = (port_u8)t->pointer,
			};
			port_sync_rom_window(m, (port_u8)t->bank);
			m[H_LOADED_ROM_BANK] = (port_u8)t->bank;
			m[R_ROMB] = (port_u8)t->bank;
			port_text_command_bcd(&r, m);
			t->pointer = r.h * 256u + r.l;
			t->destination = r.b * 256u + r.c;
			m[H_LOADED_ROM_BANK] = (port_u8)saved_bank;
			m[R_ROMB] = (port_u8)saved_bank;
			port_sync_rom_window(m, (port_u8)saved_bank);
		} else if (command == 0x03) {
			/* TextCommand_MOVE replaces the live text destination with the
			 * little-endian address embedded in the command stream. */
			unsigned saved_bank = m[H_LOADED_ROM_BANK];
			struct cpu_register_state r = {
				.b = (port_u8)(t->destination >> 8),
				.c = (port_u8)t->destination,
				.h = (port_u8)(t->pointer >> 8),
				.l = (port_u8)t->pointer,
			};
			port_sync_rom_window(m, (port_u8)t->bank);
			m[H_LOADED_ROM_BANK] = (port_u8)t->bank;
			m[R_ROMB] = (port_u8)t->bank;
			port_text_command_move(&r, m);
			t->pointer = r.h * 256u + r.l;
			t->destination = r.b * 256u + r.c;
			m[H_LOADED_ROM_BANK] = (port_u8)saved_bank;
			m[R_ROMB] = (port_u8)saved_bank;
			port_sync_rom_window(m, (port_u8)saved_bank);
		} else if (command >= 0x14 && command <= 0x16) {
			/* Preserve the original OakSpeechText2 Nidorina cry, even though
			 * the displayed picture is Nidorino. */
			static const uint8_t species[] = {0xa8, 0x97, 0x78};
			struct cpu_register_state r = {.a = species[command - 0x14]};
			port_get_cry_data(&r, m);
			music_play(m, m[0xc0ef], r.a);
			t->sound_wait = 1;
			return;
		} else {
			fprintf(stderr, "TODO(text-command): %02x at %02x:%04x\n", command, t->bank, t->pointer - 1);
			break;
		}
	}
	fprintf(stderr, "pokered-mac: text continuation stopped at %02x:%04x\n", t->bank, t->pointer);
	text_finish(t, m);
}
