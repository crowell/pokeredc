#include "platform.h"
#include <stdio.h>

void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);
void port_reds_house1_f_script(struct cpu_register_state *, port_u8 *);
void port_reds_house2_f_default_script(struct cpu_register_state *, port_u8 *);
void port_enable_auto_text_box_drawing(struct auto_text_box_state *);
void port_display_text_id_init(struct display_text_id_init_private_state *, port_u8 *);
void port_close_text_display(struct close_text_display_state *, port_u8 *);
void port_update_sprite_facing_offset_and_delay_movement(struct sprite_facing_delay_state *);
void port_oaks_lab_oak1_text(struct oaks_lab_oak1_text_state *, port_u8 *);

static unsigned word(const uint8_t *m, unsigned address)
{
	return m[address] | m[address + 1] * 256u;
}

static unsigned map_bank(uint8_t *m)
{
	struct switch_to_map_rom_bank_state s = {0};
	s.registers.a = m[0xd35e];
	s.loaded_rom_bank = m[H_LOADED_ROM_BANK];
	s.mapper_bank = m[R_ROMB];
	s.home_temp = m[0xff8b]; s.home_saved_rom_bank = m[0xffb9];
	port_switch_to_map_rom_bank(&s);
	m[H_LOADED_ROM_BANK] = s.loaded_rom_bank;
	m[R_ROMB] = s.mapper_bank;
	m[0xff8b] = s.home_temp; m[0xffb9] = s.home_saved_rom_bank;
	port_sync_rom_window(m, s.loaded_rom_bank);
	return s.loaded_rom_bank;
}

/* Banked C dispatch for RunMapScript's JP HL. Never execute ROM opcodes.
 * TODO(map-scripts): complete the boulder/NPC-movement preludes and register
 * the remaining original map functions. Missing entries are diagnosed once
 * per bank/address, not recorded as completed/proven calls. */
void map_script_tick(uint8_t *m, struct mac_game *g)
{
	unsigned bank = map_bank(m), pointer = word(m, 0xd36e);
	struct cpu_register_state r = {0};
	if (bank == 0x12 && pointer == 0x4168) {
		port_reds_house1_f_script(&r, m);
		return;
	}
	if (bank == 0x17 && pointer == 0x40b0) {
		struct auto_text_box_state box = {0};
		port_enable_auto_text_box_drawing(&box);
		m[0xcf0c] = box.auto_text_box_drawing_control;
		m[0xcc3c] = box.do_not_wait_for_button_press;
		/* CallFunctionInTable: use the original linked pointer table. */
		unsigned index = m[0xd60c];
		if (index < 2) {
			unsigned target = word(m, 0x40bc + index * 2);
			if (target == 0x40c0) {
				port_reds_house2_f_default_script(&r, m);
				return;
			}
			if (target == 0x40ce) return; /* Original RedsHouse2FNoopScript RET. */
		}
	}
	unsigned key = bank * 65536u + pointer;
	if (g->missing_map_script != key) {
		fprintf(stderr, "TODO(RunMapScript): map=%02x C callback %02x:%04x\n", m[0xd35e], bank, pointer);
		g->missing_map_script = key;
	}
}

/* Explicit C continuations of the two text_asm selectors. Healing is a
 * separate resumable sequence, not equivalent to displaying its first line.
 * TODO(proof): prove selectors and implement RedsHouse1FMomHealScript. */
static unsigned map_text_callback(uint8_t *m, unsigned bank, unsigned pointer)
{
	if (bank == 0x07 && pointer == 0x5248) {
		struct oaks_lab_oak1_text_state oak = {0};
		port_oaks_lab_oak1_text(&oak, m);
		return oak.selected_text_low | oak.selected_text_high * 256u;
	}
	if (bank == 0x12 && pointer == 0x416f) {
		if (!(m[0xd72e] & 8)) return 0x4185;
		fprintf(stderr, "TODO(RedsHouse1FMomHealScript): heal/music/fade continuation\n");
		return 0;
	}
	if (bank == 0x12 && pointer == 0x41c6)
		return m[0xc109] == 4 ? 0x41da : 0x41df;
	fprintf(stderr, "TODO(text_asm): C callback %02x:%04x\n", bank, pointer);
	return 0;
}

int map_text_open(uint8_t *m, struct mac_game *g, unsigned id)
{
	unsigned saved_bank = m[H_LOADED_ROM_BANK];
	unsigned bank = map_bank(m);
	if (!id) {
		/* TODO(DisplayStartMenu): connect its full input/child-menu loop. */
		fprintf(stderr, "TODO(DisplayStartMenu): menu continuation not implemented\n");
		return 0;
	}
	unsigned text_id = id;
	if (id <= m[0xd4e1]) text_id = m[0xd4e4 + (id - 1) * 2 + 1];
	if (!text_id) return 0;
	unsigned table = word(m, 0xd36c);
	if (table < 0x4000 || table + text_id * 2 > 0x8000) return 0;
	unsigned pointer = word(m, table + (text_id - 1) * 2);
	if (pointer < 0x4000 || pointer >= 0x8000) return 0;
	if (m[pointer] == 8) pointer = map_text_callback(m, bank, pointer);
	if (!pointer) return 0;
	if (m[pointer] != 0 && m[pointer] != 0x17) {
		fprintf(stderr, "TODO(map-text): special marker %02x at %02x:%04x\n", m[pointer], bank, pointer);
		return 0;
	}
	g->map_text_bank = saved_bank;
	m[0xff8c] = (uint8_t)id;
	struct display_text_id_init_private_state init = {0};
	port_display_text_id_init(&init, m);
	map_bank(m);
	m[0xffd5] = 30;
	m[0xcf13] = (uint8_t)id;
	if (id <= m[0xd4e1]) {
		unsigned offset = id * 16;
		struct sprite_facing_delay_state s = {0};
		s.current_offset = (uint8_t)offset;
		s.movement_delay = m[0xc208 + offset];
		s.facing_direction = m[0xc109 + offset];
		s.animation_frame = m[0xc108 + offset];
		s.intra_animation_frame = m[0xc107 + offset];
		s.image_index = m[0xc102 + offset];
		s.movement_status = m[0xc101 + offset];
		port_update_sprite_facing_offset_and_delay_movement(&s);
		m[0xc208 + offset] = s.movement_delay;
		m[0xc108 + offset] = s.animation_frame;
		m[0xc107 + offset] = s.intra_animation_frame;
		m[0xc102 + offset] = s.image_index;
		m[0xc101 + offset] = s.movement_status;
	}
	text_begin(&g->text, m, bank, pointer);
	g->map_text_state = 1;
	return 1;
}

void map_text_tick(uint8_t *m, struct mac_game *g)
{
	if (g->map_text_state == 1) {
		text_tick(&g->text, m, m[H_JOYPRESSED], m[H_JOYHELD]);
		if (g->text.active) return;
		g->map_text_state = m[0xcc3c] ? 3 : 2;
		return;
	}
	if (g->map_text_state == 2) {
		if (!(m[H_JOYPRESSED] & (PAD_A | PAD_B))) return;
		g->map_text_state = 3;
	}
	if (g->map_text_state == 3) {
		if (m[H_JOYHELD] & PAD_A) return;
		/* CloseTextDisplay's first DelayFrame hides the window before tile
		 * patterns change. Keep its remaining C continuation on the next frame. */
		m[H_WY] = 0x90;
		g->map_text_state = 4;
		return;
	}
	struct close_text_display_state close = {0};
	close.saved_a = (uint8_t)g->map_text_bank;
	close.map_pal_offset = m[0xd35d];
	/* LoadGBPal reads FadePal4 minus wMapPalOffset. */
	unsigned palette = 0x2116 - close.map_pal_offset;
	close.palette[0] = m[palette];
	close.palette[1] = m[palette + 1];
	close.palette[2] = m[palette + 2];
	port_close_text_display(&close, m);
	g->map_text_state = 0;
	g->overworld_pressed = 0;
}
