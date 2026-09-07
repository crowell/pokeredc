#include "platform.h"
#include <string.h>

void port_clear_screen(struct cpu_register_state *, port_u8 *);
void port_get_mon_header(struct cpu_register_state *, port_u8 *);
void port_display_intro_name_text_box(struct cpu_register_state *, port_u8 *);
void port_oak_speech_slide_pic_right(struct cpu_register_state *);
void port_oak_speech_slide_pic_left(struct cpu_register_state *, port_u8 *);
void port_oak_speech_slide_pic_common(struct cpu_register_state *, port_u8 *);
void port_get_default_name(struct cpu_register_state *, port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);
void port_place_menu_cursor(struct place_menu_cursor_state *, port_u8 *);
void port_display_naming_screen(struct cpu_register_state *, port_u8 *);
void port_print_alphabet(struct cpu_register_state *, port_u8 *);
void port_print_nickname_and_underscores(struct cpu_register_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_text_box_border(struct text_box_border_state *, port_u8 *);
void port_load_hp_bar_and_status_tile_patterns_on(struct cpu_register_state *, port_u8 *);
void port_reset_player_sprite_data(struct cpu_register_state *, port_u8 *);
void port_prepare_oam_data(struct cpu_register_state *, port_u8 *);
void port_copy_video_data(struct cpu_register_state *, port_u8 *);
void port_load_text_box_tile_patterns(struct load_text_box_tile_patterns_state *, port_u8 *);

enum { PICTURE, MON, INTRO_FADE, FADE_OUT, FADE_IN, MOVE_LEFT, TEXT,
	NAME, SHRINK, SMALL_PLAYER, CLEAR_PIC, ENTER, PAUSE, PICTURE_KEEP,
	PLAYER_TILES };
struct oak_action { unsigned kind, bank, arg; };

/* OakSpeech's actual call order and ROM text, not a replacement script.
 * TODO(proof): verify the resumable orchestration, including exact delays
 * inside graphics transfers and the shared slide routine. */
static const struct oak_action speech[] = {
	{PICTURE, 0x13, 0x615f}, {INTRO_FADE, 0, 0}, {TEXT, 1, 0x6253},
	{FADE_OUT, 0, 0}, {MON, 0, 0xa7}, {MOVE_LEFT, 0, 0}, {TEXT, 1, 0x6258},
	{FADE_OUT, 0, 0}, {PICTURE, 4, 0x6ede}, {MOVE_LEFT, 0, 0},
	{TEXT, 1, 0x6262}, {NAME, 0, 0}, {TEXT, 1, 0x699f},
	{FADE_OUT, 0, 0}, {PICTURE, 0x13, 0x6049}, {INTRO_FADE, 0, 0},
	{TEXT, 1, 0x6267}, {NAME, 0, 1}, {TEXT, 1, 0x69e7},
	{FADE_OUT, 0, 0}, {PICTURE, 4, 0x6ede}, {FADE_IN, 0, 0},
	{TEXT, 1, 0x626c}, {SHRINK, 0, 0}, {PLAYER_TILES, 0, 0},
	{PICTURE_KEEP, 4, 0x6fe8}, {PAUSE, 0, 4},
	{PICTURE_KEEP, 4, 0x7042}, {SMALL_PLAYER, 0, 0}, {CLEAR_PIC, 0, 0},
	{FADE_OUT, 0, 0}, {ENTER, 0, 0}
};

static void bank1(uint8_t *m)
{
	m[H_LOADED_ROM_BANK] = m[R_ROMB] = 1;
	port_sync_rom_window(m, 1);
}

static void cursor(uint8_t *m)
{
	struct place_menu_cursor_state s = {0};
	s.top_y = m[0xcc24]; s.top_x = m[0xcc25];
	s.current_item = m[0xcc26]; s.last_item = m[0xcc2a];
	s.tile_behind = m[0xcc27]; s.layout_flags = m[0xfff6];
	s.cursor_low = m[0xcc30]; s.cursor_high = m[0xcc31];
	port_place_menu_cursor(&s, m);
	m[0xcc2a] = s.last_item; m[0xcc27] = s.tile_behind;
	m[0xcc30] = s.cursor_low; m[0xcc31] = s.cursor_high;
}

static void erase_cursor(uint8_t *m)
{
	unsigned address = m[0xcc30] + m[0xcc31] * 256u;
	if (address >= W_TILE_MAP && address < W_TILE_MAP + 360)
		m[address] = m[0xcc27];
}

static void clear(uint8_t *m)
{
	struct cpu_register_state r = {0};
	port_clear_screen(&r, m);
}

static void textbox_tiles(uint8_t *m)
{
	struct load_text_box_tile_patterns_state s = {0};
	s.lcd_control = m[R_LCDC];
	s.transfer.loaded_bank = m[H_LOADED_ROM_BANK];
	s.transfer.rom_bank = m[R_ROMB];
	port_load_text_box_tile_patterns(&s, m);
}

static void load_custom_name_screen(struct mac_kernel *k, uint8_t *m,
	const struct mac_rom *rom, struct mac_game *g)
{
	struct cpu_register_state r = {0};
	clear(m);
	m[0xd07d] = (port_u8)g->naming_rival;
	port_display_naming_screen(&r, m);
	port_load_hp_bar_and_status_tile_patterns_on(&r, m);
	kernel_copy_video_data_double(k, m, rom, 1, 0x6767, 0x8f00, 1);
	struct text_box_border_state box = {0};
	box.registers.h = 0xc3; box.registers.l = 0xf0;
	box.registers.b = 9; box.registers.c = 18;
	port_text_box_border(&box, m);
	bank1(m);
	/* PrintNamingText's player/rival strings, through PlaceString. */
	r.h = 0xc3; r.l = 0xb4; r.d = 0x69;
	r.e = g->naming_rival ? 0x45 : 0x3f;
	port_place_string(&r, m);
	r.h = r.b; r.l = r.c; r.d = 0x69; r.e = 0x4d;
	port_place_string(&r, m);
	port_print_alphabet(&r, m);
	port_print_nickname_and_underscores(&r, m);
	cursor(m);
	m[R_BGP] = 0xe4;
	g->naming = 2;
	g->oak_timer = 3; /* PrintAlphabet ends in Delay3: publish all BG thirds. */
}

static void finish_name(uint8_t *m, struct mac_game *g, int custom)
{
	struct cpu_register_state r = {0};
	unsigned destination = g->naming_rival ? 0xd34a : 0xd158;
	bank1(m);
	if (custom) {
		if (m[0xcf4b] == 0x50) return; /* Original rejects empty names. */
		r.h = 0xcf; r.l = 0x4b;
		r.d = (port_u8)(destination >> 8); r.e = (port_u8)destination;
		r.c = 11;
		port_copy_data(&r, m);
		m[0xd730] &= (uint8_t)~0x40;
		textbox_tiles(m);
		clear(m);
		picture_trainer(m, g->naming_rival ? 0x13 : 4,
			g->naming_rival ? 0x6049 : 0x6ede);
		g->oak_timer = 6; /* Submit white-out + ChooseName's ClearScreen/Delay3. */
	} else {
		r.a = m[0xcc26]; r.h = 0x6a; r.l = 0xf2;
		if (g->naming_rival) { r.h = 0x6b; r.l = 0x08; }
		port_get_default_name(&r, m);
		/* GetDefaultName's CopyData continuation is outside its old proof. */
		r.h = r.d; r.l = r.e; r.d = 0xcd; r.e = 0x6d; r.b = 0; r.c = 20;
		port_copy_data(&r, m);
		r.d = (port_u8)(destination >> 8); r.e = (port_u8)destination;
		port_oak_speech_slide_pic_left(&r, m);
		port_oak_speech_slide_pic_common(&r, m);
		g->oak_timer = 31; /* 10 + Delay3 + six Delay3 passes. */
	}
	g->naming = 0;
}

/* DisplayNamingScreen's English-ROM button continuations, in the original
 * priority (down, up, left, right, start, select, B, A). TODO(proof): extract
 * and prove each button continuation; add kana modifiers for Japanese data. */
static void naming_tick(struct mac_kernel *k, uint8_t *m,
	const struct mac_rom *rom, struct mac_game *g)
{
	uint8_t pressed = m[H_JOYPRESSED];
	struct cpu_register_state r = {0};
	bank1(m);
	if (g->naming == 1) {
		if (pressed & PAD_DOWN) m[0xcc26] = (m[0xcc26] + 1) % 4;
		else if (pressed & PAD_UP) m[0xcc26] = (m[0xcc26] + 3) % 4;
		else if (pressed & PAD_A) {
			if (m[0xcc26]) finish_name(m, g, 0);
			else load_custom_name_screen(k, m, rom, g);
			return;
		}
		cursor(m);
		return;
	}
	if (!pressed) return;
	erase_cursor(m);
	unsigned row = m[0xcc26], column = m[0xcc25];
	unsigned length = m[0xcee9];
	int submit = 0;
	if (pressed & PAD_DOWN) { row = row == 6 ? 1 : row + 1; if (row == 6 || row == 1) column = 1; }
	else if (pressed & PAD_UP) { row = row == 1 ? 6 : row - 1; if (row == 6) column = 1; }
	else if (pressed & PAD_LEFT) { if (row != 6) column = column == 1 ? 17 : column - 2; }
	else if (pressed & PAD_RIGHT) { if (row != 6) column = column == 17 ? 1 : column + 2; }
	else if (pressed & PAD_START) submit = 1;
	else if (pressed & PAD_SELECT) m[0xceeb] ^= 1;
	else if (pressed & PAD_B) { if (length) m[0xcf4b + --length] = 0x50; }
	else if (pressed & PAD_A) {
		if (row == 5 && column == 17) submit = 1;
		else if (row == 6 && column == 1) m[0xceeb] ^= 1;
		else if (length < 7) {
			m[0xcf4b + length++] = m[W_TILE_MAP + (3 + row * 2) * 20 + column + 1];
			m[0xcf4b + length] = 0x50;
			music_play(m, m[0xc0ef], 0x90); /* SFX_PRESS_AB */
		}
	}
	m[0xcc26] = (uint8_t)row; m[0xcc25] = (uint8_t)column;
	if (submit) {
		finish_name(m, g, 1);
		if (g->naming) cursor(m); /* Empty submission keeps the naming cursor. */
		return;
	}
	port_print_alphabet(&r, m);
	if ((pressed & PAD_SELECT) || ((pressed & PAD_A) && row == 6))
		g->oak_timer = 3;
	port_print_nickname_and_underscores(&r, m);
	cursor(m);
}

void oak_begin(struct mac_game *g)
{
	g->oak_step = g->oak_timer = g->oak_effect = g->naming = 0;
	memset(&g->text, 0, sizeof(g->text));
}

void oak_tick(struct mac_kernel *k, uint8_t *m,
	const struct mac_rom *rom, struct mac_game *g)
{
	struct cpu_register_state r = {0};
	if (g->oak_timer) {
		unsigned remaining = g->oak_timer--;
		if (g->oak_effect == INTRO_FADE) {
			m[R_BGP] = rom->data[0x4000 + 0x2282 + (60 - remaining) / 10];
		} else if (g->oak_effect == FADE_OUT || g->oak_effect == FADE_IN) {
			unsigned i = (24 - remaining) / 8;
			unsigned source = g->oak_effect == FADE_OUT ? 0x211c + i * 3 : 0x211f - i * 3;
			m[R_BGP] = m[source]; m[R_OBP0] = m[source + 1]; m[R_OBP1] = m[source + 2];
		} else if (g->oak_effect == MOVE_LEFT) {
			if (remaining < 16 && remaining > 1) { m[R_BGP] = 0xe4; m[R_WX] = (uint8_t)(119 - (16 - remaining) * 8); }
		} else if (g->oak_effect == CLEAR_PIC) {
			/* PrepareOAMData runs in VBlank while DelayFrames waits. */
			bank1(m);
			port_prepare_oam_data(&r, m);
		}
		if (!g->oak_timer) g->oak_effect = PAUSE;
		return;
	}
	if (g->text.active) { text_tick(&g->text, m, m[H_JOYPRESSED], m[H_JOYHELD]); return; }
	if (g->naming) { naming_tick(k, m, rom, g); return; }
	if (g->oak_step >= sizeof(speech) / sizeof(*speech)) return;
	struct oak_action a = speech[g->oak_step++];
	bank1(m);
	switch (a.kind) {
	case PICTURE:
		clear(m); picture_trainer(m, a.bank, a.arg); break;
	case PICTURE_KEEP:
		picture_trainer(m, a.bank, a.arg); break;
	case MON:
		clear(m); m[0xd0b5] = m[0xcf91] = (port_u8)a.arg;
		port_get_mon_header(&r, m); picture_mon(m, W_TILE_MAP + 4 * 20 + 6, 1); break;
	case INTRO_FADE: case FADE_OUT: case FADE_IN:
		g->oak_effect = a.kind; g->oak_timer = a.kind == INTRO_FADE ? 60 : 24; break;
	case MOVE_LEFT:
		m[R_WX] = 119; g->oak_effect = MOVE_LEFT; g->oak_timer = 16; break;
	case TEXT: text_begin(&g->text, m, a.bank, a.arg); break;
	case NAME:
		g->naming = 1; g->naming_rival = a.arg;
		port_oak_speech_slide_pic_right(&r);
		port_oak_speech_slide_pic_common(&r, m);
		r.d = 0x6a; r.e = a.arg ? 0xbe : 0xa8;
		port_display_intro_name_text_box(&r, m); cursor(m);
		g->oak_timer = 18; break;
	case SHRINK:
		music_play(m, m[0xc0ef], 0x9c); /* SFX_SHRINK */
		g->oak_timer = 4; break;
	case PLAYER_TILES:
		r.b = 5; r.c = 12; r.d = 0x41; r.e = 0x80; r.h = 0x80;
		port_copy_video_data(&r, m); break;
	case SMALL_PLAYER:
		port_reset_player_sprite_data(&r, m);
		music_fade(m, 2, 0xff, 10); g->oak_timer = 20; break;
	case CLEAR_PIC:
		for (unsigned y = 5; y < 12; ++y) memset(m + W_TILE_MAP + y * 20 + 6, 0x7f, 7);
		textbox_tiles(m);
		m[0xcfcb] = 1;
		g->oak_effect = CLEAR_PIC; g->oak_timer = 50; break;
	case PAUSE: g->oak_timer = a.arg; break;
	case ENTER:
		clear(m); g->phase = MAC_PHASE_ENTER_MAP; g->frames_in_phase = 0; break;
	}
}
