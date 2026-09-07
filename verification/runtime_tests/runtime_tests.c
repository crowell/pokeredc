#include "platform.h"
#include <assert.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

port_u8 port_uncompress_sprite_data(struct cpu_register_state *, port_u8 *);
void port_get_mon_header(struct cpu_register_state *, port_u8 *);
void port_load_uncompressed_sprite_data(struct cpu_register_state *, port_u8 *);
void port_load_font_tile_patterns_on(struct cpu_register_state *, port_u8 *);
void port_copy_screen_tile_buffer_to_vram(struct cpu_register_state *, port_u8 *);

static void capture_frame(const uint8_t *m, const char *label)
{
	const char *directory = getenv("POKERED_TEST_FRAMES_DIR");
	if (!directory) return;
	char path[1024];
	assert(snprintf(path, sizeof(path), "%s/%s.ppm", directory, label) < (int)sizeof(path));
	FILE *file = fopen(path, "wb");
	assert(file);
	uint32_t pixels[GB_SCREEN_W * GB_SCREEN_H];
	video_render(m, pixels);
	fprintf(file, "P6\n160 144\n255\n");
	for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; ++i) {
		uint8_t rgb[] = {(uint8_t)(pixels[i] >> 16), (uint8_t)(pixels[i] >> 8), (uint8_t)pixels[i]};
		assert(fwrite(rgb, 1, 3, file) == 3);
	}
	assert(fclose(file) == 0);
}

static void test_display_transfers(uint8_t *m, const struct mac_rom *rom)
{
	gb_reset_memory(m, rom);
	m[H_LOADED_ROM_BANK] = m[R_ROMB] = 6;
	port_sync_rom_window(m, 6);
	struct cpu_register_state r = {0};
	port_load_font_tile_patterns_on(&r, m);
	const uint8_t *source = rom->data + 4 * 0x4000 + 0x1a80;
	for (unsigned i = 0; i < 1024; ++i)
		assert(m[0x8800 + i * 2] == source[i] && m[0x8801 + i * 2] == source[i]);
	assert(m[H_LOADED_ROM_BANK] == 6 && m[R_ROMB] == 6);
	assert(memcmp(m + 0x4000, rom->data + 6 * 0x4000, 0x4000) == 0);
	for (unsigned i = 0; i < 360; ++i) m[W_TILE_MAP + i] = (uint8_t)(i * 13);
	r.b = 0x9c;
	port_copy_screen_tile_buffer_to_vram(&r, m);
	for (unsigned row = 0; row < 18; ++row)
		assert(memcmp(m + W_TILE_MAP + row * 20, m + 0x9c00 + row * 32, 20) == 0);
	puts("PASS: all font chunks and all three window tilemap transfers, bank restored");
}

static void solid_tile(uint8_t *m, unsigned tile, unsigned color)
{
	for (unsigned row = 0; row < 8; ++row) {
		m[0x8000 + tile * 16 + row * 2] = color & 1 ? 0xff : 0;
		m[0x8001 + tile * 16 + row * 2] = color & 2 ? 0xff : 0;
	}
}

static void test_dmg_video(uint8_t *m, const struct mac_rom *rom)
{
	uint32_t pixels[GB_SCREEN_W * GB_SCREEN_H];
	gb_reset_memory(m, rom);
	m[R_LCDC] = 0x93; /* LCD, unsigned tiles, OBJ, BG. */
	m[R_BGP] = 0; /* All mapped shades equal: priority still uses raw color. */
	m[R_OBP0] = 0xe4;
	solid_tile(m, 0, 1); solid_tile(m, 1, 2); solid_tile(m, 2, 3);
	m[OAM_START] = 16; m[OAM_START + 1] = 24; m[OAM_START + 2] = 1;
	m[OAM_START + 3] = 0x80;
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[0]); /* Raw BG 1 hides the sprite. */
	solid_tile(m, 0, 0); m[R_BGP] = 0xff;
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[2]); /* Raw BG 0 does not hide it. */
	solid_tile(m, 0, 1); m[R_BGP] = 0xe4;
	m[OAM_START + 4] = 16; m[OAM_START + 5] = 24; m[OAM_START + 6] = 2;
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[1]); /* Hidden winning OBJ masks other OBJ. */
	m[OAM_START + 3] = 0; m[OAM_START + 5] = 22;
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[3]); /* Smaller X beats earlier OAM. */
	m[OAM_START + 5] = 24;
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[2]); /* Equal X: earlier OAM wins. */
	solid_tile(m, 1, 0);
	video_render(m, pixels);
	assert(pixels[16] == dmg_palette[3]); /* Transparent winning OBJ exposes next. */
	memset(m + OAM_START, 0, OAM_SIZE);
	for (unsigned i = 0; i < 11; ++i) {
		m[OAM_START + i * 4] = 16;
		m[OAM_START + i * 4 + 2] = 2;
	}
	m[OAM_START + 10 * 4 + 1] = 8;
	video_render(m, pixels);
	assert(pixels[0] == dmg_palette[1]); /* X-hidden first ten still consume slots. */
	m[OAM_START] = 0;
	video_render(m, pixels);
	assert(pixels[0] == dmg_palette[3]); /* Y-hidden entries do not. */
	memset(m + OAM_START, 0, OAM_SIZE);
	m[R_LCDC] |= LCDC_SPRITE_SIZE_16;
	solid_tile(m, 2, 2); solid_tile(m, 3, 3);
	m[OAM_START] = 16; m[OAM_START + 1] = 8;
	m[OAM_START + 2] = 3; m[OAM_START + 3] = 0x40;
	video_render(m, pixels);
	assert(pixels[0] == dmg_palette[3] && pixels[15 * GB_SCREEN_W] == dmg_palette[2]);
	m[R_LCDC] = 0xf1; /* Window on BG1, no OBJ. */
	m[R_WX] = 5; m[R_WY] = 0;
	m[0x9c00] = 3;
	memset(m + 0x8030, 0, 16); m[0x8031] = 0x20;
	video_render(m, pixels);
	assert(pixels[0] == dmg_palette[2]); /* WX<7 clips source, not just destination. */
	m[R_LCDC] &= (uint8_t)~LCDC_BG_ON; m[R_BGP] = 0xff;
	video_render(m, pixels);
	assert(pixels[0] == dmg_palette[0]); /* DMG BG-off overrides window and BGP. */
	puts("PASS: DMG raw-color/OBJ priority, ten-OBJ selection, 8x16 flip, window clipping/disable");
}

static uint8_t reverse_bits(uint8_t value)
{
	uint8_t result = 0;
	for (unsigned i = 0; i < 8; ++i) { result = (uint8_t)((result << 1) | (value & 1)); value >>= 1; }
	return result;
}

static size_t read_asset(const char *path, uint8_t *out, size_t capacity)
{
	FILE *file = fopen(path, "rb");
	assert(file);
	size_t size = fread(out, 1, capacity, file);
	assert(!ferror(file) && feof(file));
	fclose(file);
	return size;
}

/* Independent expected bytes are the original uncompressed graphics, not
 * another implementation of the same decoding algorithm. This regression
 * check does NOT claim a symbolic proof of the composed SM83 routine. */
static void test_pictures(uint8_t *memory, const struct mac_rom *rom)
{
	glob_t assets = {0};
	const char *patterns[] = {"../gfx/pokemon/front/*.pic",
		"../gfx/pokemon/back/*.pic", "../gfx/trainers/*.pic",
		"../gfx/player/*.pic"};
	for (unsigned i = 0; i < sizeof(patterns) / sizeof(*patterns); ++i) {
		int result = glob(patterns[i], i ? GLOB_APPEND : 0, NULL, &assets);
		assert(result == 0 || result == GLOB_NOMATCH);
	}
	assert(assets.gl_pathc >= 300);
	unsigned modes[3][2] = {{0}};
	for (size_t file = 0; file < assets.gl_pathc; ++file) {
		uint8_t compressed[0x4000], expected[2048];
		char path[1024];
		const char *pic = assets.gl_pathv[file];
		assert(strlen(pic) + 2 < sizeof(path));
		snprintf(path, sizeof(path), "%.*s.2bpp", (int)strlen(pic) - 4, pic);
		size_t size = read_asset(pic, compressed, sizeof(compressed));
		size_t raw_size = read_asset(path, expected, sizeof(expected));
		unsigned width = compressed[0] >> 4, height = compressed[0] & 15;
		assert(raw_size == width * height * 16);
		gb_reset_memory(memory, rom);
		memcpy(memory + PORT_ROM_BACKING_BASE + 0x4000 * 0x20,
			compressed, size);
		memory[0xd0ab] = 0;
		memory[0xd0ac] = 0x40;
		struct cpu_register_state registers = {.a = 0x20, .f = 0xb0};
		assert(port_uncompress_sprite_data(&registers, memory));
		assert(registers.a == 1 && registers.f == 0xb0);
		assert(memory[H_LOADED_ROM_BANK] == 1);
		assert(memcmp(memory + 0x4000, rom->data + 0x4000, 0x4000) == 0);
		assert(memory[0xd0a9] <= 2);
		++modes[memory[0xd0a9]][compressed[1] >> 7];
		for (unsigned x = 0; x < width; ++x)
			for (unsigned y = 0; y < height; ++y)
				for (unsigned row = 0; row < 8; ++row)
					for (unsigned plane = 0; plane < 2; ++plane) {
						unsigned src = ((y * width + x) * 8 + row) * 2 + plane;
						unsigned dest = 0xa188 + plane * 392 +
							(x * height + y) * 8 + row;
						if (expected[src] != memory[dest]) {
							fprintf(stderr, "%s: (%u,%u) row %u plane %u: expected %02x got %02x, mode %u order %u\n",
								pic,x,y,row,plane,expected[src],memory[dest],memory[0xd0a9],compressed[1] >> 7);
							abort();
						}
					}
		/* Exercise the complete alignment/interlace/VRAM pipeline, including
		 * the mirrored decode used by Oak and battles. */
		for (unsigned flipped = 0; flipped < 2; ++flipped) {
			memory[0xd0aa] = (uint8_t)flipped;
			memory[0xd0ab] = 0; memory[0xd0ac] = 0x40;
			registers.a = 0x20;
			assert(port_uncompress_sprite_data(&registers, memory));
			registers.a = registers.c = compressed[0];
			registers.d = 0x90; registers.e = 0;
			port_load_uncompressed_sprite_data(&registers, memory);
			uint8_t aligned[784] = {0};
			for (unsigned x = 0; x < width; ++x)
				for (unsigned y = 0; y < height; ++y)
					for (unsigned byte = 0; byte < 16; ++byte) {
						uint8_t value = expected[(y * width + x) * 16 + byte];
						aligned[((x + (8 - width) / 2) * 7 + y + 7 - height) * 16 + byte] =
							flipped ? reverse_bits(value) : value;
					}
			if (memcmp(memory + 0x9000, aligned, sizeof(aligned))) {
				fprintf(stderr, "%s: aligned VRAM differs (flip=%u)\n", pic, flipped);
				abort();
			}
		}
	}
	printf("PASS: %zu original pictures decoded byte-for-byte, normal/mirrored VRAM\n", assets.gl_pathc);
	for (unsigned mode = 0; mode < 3; ++mode)
		printf("  mode %u: %u first-plane-0, %u first-plane-1\n", mode, modes[mode][0], modes[mode][1]);
	globfree(&assets);
}

static void test_mode_zero(uint8_t *m, const struct mac_rom *rom)
{
	/* One 8x8 blank tile: order, initial-zero marker, length-32 encoding
	 * 11110 00001, mode 0, zero marker, length-32. Neither shipped asset
	 * chooses mode 0, so test both buffer orders with this independent stream. */
	for (unsigned order = 0; order < 2; ++order) {
		gb_reset_memory(m, rom);
		uint8_t *pic = m + PORT_ROM_BACKING_BASE + 32 * 0x4000;
		memset(pic, 0, 8); pic[0] = 0x11;
		const char *bits = "001111000001001111000001";
		for (unsigned b = 0; bits[b]; ++b)
			pic[1 + b / 8] |= (uint8_t)((bits[b] - '0') << (7 - b % 8));
		pic[1] |= order << 7;
		m[0xd0ab] = 0; m[0xd0ac] = 0x40;
		struct cpu_register_state r = {.a = 32};
		assert(port_uncompress_sprite_data(&r, m));
		assert(m[0xd0a9] == 0);
		for (unsigned i = 0; i < 784; ++i) assert(m[0xa188 + i] == 0);
	}
	puts("PASS: mode-0 zero runs in both buffer orders");
}

static void test_mon_header(uint8_t *memory, const struct mac_rom *rom)
{
	gb_reset_memory(memory, rom);
	struct cpu_register_state registers = {0};
	memory[0xd0b5] = 0xb0; /* CHARMANDER */
	port_get_mon_header(&registers, memory);
	assert(memory[0xd0c2] == 0x55);
	assert(memory[0xd0c3] == 0x5c && memory[0xd0c4] == 0x5c);
	assert(memory[H_LOADED_ROM_BANK] == 1);
	assert(memcmp(memory + 0x4000, rom->data + 0x4000, 0x4000) == 0);
	puts("PASS: GetMonHeader reads BaseStats from the selected ROM bank");
}

static void frame(uint8_t *m, const struct mac_rom *rom,
	struct mac_kernel *kernel, struct mac_game *game, uint8_t pad)
{
	m[H_JOYINPUT] = pad;
	kernel_vblank(kernel, m, rom);
	music_tick(m);
	game_tick(kernel, m, rom, game);
}

static void test_audio_fade(uint8_t *m, const struct mac_rom *rom)
{
	gb_reset_memory(m, rom);
	m[0xc0ef] = m[0xc0f0] = 8;
	m[0xcfca] = 0xea;
	m[0xff24] = 0x77;
	music_fade(m, 2, 0xef, 10);
	assert(m[0xcfc7] == 0xef && m[0xcfc8] == 10 && m[0xcfc9] == 10);
	for (unsigned f = 1; f <= 87; ++f) {
		music_tick(m);
		assert(m[0xc0ef] == 8); /* old bank is retained through fade */
		assert(m[0xff24] == (7 - f / 11) * 0x11);
	}
	music_tick(m);
	assert(m[0xcfc7] == 0 && m[0xc0ef] == 2 && m[0xc0f0] == 2);
	assert(m[0xc026] || m[0xc027] || m[0xc028]);
	puts("PASS: 88-frame volume fade preserves old bank, then starts queued music");
}

static void test_intro_input(uint8_t *m, const struct mac_rom *rom)
{
	struct mac_kernel k;
	struct mac_game g = {0};
	gb_reset_memory(m, rom); kernel_init(&k); game_boot(&k, m, rom, &g);
	for (unsigned f = 0; f < 245; ++f) frame(m, rom, &k, &g, 0);
	assert(g.scene == 2);
	frame(m, rom, &k, &g, PAD_A);
	for (unsigned f = 0; f < 6; ++f) frame(m, rom, &k, &g, 0);
	assert(g.phase == MAC_PHASE_INTRO && g.scene == 7);
	frame(m, rom, &k, &g, PAD_A);
	assert(g.scene == 8);
	puts("PASS: shooting-star interruption enters battle intro; its first movement can then be skipped");
}

static void test_text_command_ram_composition(uint8_t *m,
	const struct mac_rom *rom)
{
	struct mac_text text;
	unsigned stream = PORT_ROM_BACKING_BASE + 0x6000;

	gb_reset_memory(m, rom);
	m[H_LOADED_ROM_BANK] = m[R_ROMB] = 7;
	port_sync_rom_window(m, 7);
	/* TX_RAM wNameBuffer; TX_START "C"; TX_END. */
	const uint8_t commands[] = {0x01, 0x00, 0xd0, 0x00, 0x82, 0x50, 0x50};
	memcpy(m + stream, commands, sizeof(commands));
	m[0xd000] = 0x80;
	m[0xd001] = 0x81;
	m[0xd002] = 0x50;
	text_begin(&text, m, 1, 0x6000);
	for (unsigned frame = 0; frame != 16 && text.active; ++frame)
		text_tick(&text, m, 0, 0);
	assert(!text.active);
	assert(m[W_TILE_MAP + 14 * 20 + 1] == 0x80);
	assert(m[W_TILE_MAP + 14 * 20 + 2] == 0x81);
	assert(m[W_TILE_MAP + 14 * 20 + 3] == 0x82);
	assert(m[H_LOADED_ROM_BANK] == 7 && m[R_ROMB] == 7);
	puts("PASS: mac text loop composes TX_RAM and resumes the ROM command stream");
}

static void test_map_dialogue(uint8_t *m, const struct mac_rom *rom,
	struct mac_kernel *k, struct mac_game *g, unsigned id, const uint8_t *expected_tiles)
{
	uint8_t tiles[360];
	memcpy(tiles, expected_tiles ? expected_tiles : m + W_TILE_MAP, sizeof(tiles));
	unsigned x = m[0xd362], y = m[0xd361], prompts = 0;
	assert(!m[0xcfc5]);
	if (!g->map_text_state) assert(map_text_open(m, g, id));
	assert((m[R_LCDC] & LCDC_WINDOW_ON) && m[H_WY] == 0);
	assert(m[H_AUTO_BG_TRANSFER_DEST] == 0 && m[H_AUTO_BG_TRANSFER_DEST + 1] == 0x9c);
	uint8_t previous = 0;
	unsigned f;
	for (f = 0; f < 6000 && g->map_text_state; ++f) {
		uint8_t pad = 0;
		if (!previous && ((g->text.active && g->text.string.waiting) || g->map_text_state == 2)) {
			pad = PAD_A; ++prompts;
		}
		frame(m, rom, k, g, pad);
		if (f == 60) capture_frame(m, id == 1 ? "mom-dialogue" : "tv-dialogue");
		previous = pad;
		assert(m[0xd362] == x && m[0xd361] == y);
	}
	assert(f < 6000 && prompts && !g->map_text_state);
	assert(m[H_WY] == 0x90 && !m[H_AUTO_BG_TRANSFER_ENABLED]);
	assert(memcmp(tiles, m + W_TILE_MAP, sizeof(tiles)) == 0);
	capture_frame(m, id == 1 ? "after-mom" : "after-tv");
	printf("PASS: house dialogue id %u, %u manual prompts, map restored\n", id, prompts);
}

static void test_talk_to_mom_input(uint8_t *m, const struct mac_rom *rom,
	struct mac_kernel *k, struct mac_game *g)
{
	/* Branch this fixture without altering the separately tested door route. */
	uint8_t *saved = malloc(GB_STORAGE_SIZE);
	assert(saved);
	memcpy(saved, m, GB_STORAGE_SIZE);
	struct mac_kernel saved_kernel = *k;
	struct mac_game saved_game = *g;
	unsigned f;
	for (f = 0; f < 600; ++f) {
		uint8_t pad = m[0xd361] < 4 ? PAD_DOWN : m[0xd362] > 6 ? PAD_LEFT : 0;
		frame(m, rom, k, g, pad);
		if (m[0xd361] == 4 && m[0xd362] == 6 && !m[0xcfc5]) break;
	}
	assert(f < 600);
	for (unsigned i = 0; i < 4; ++i) frame(m, rom, k, g, 0);
	uint8_t map_tiles[360];
	memcpy(map_tiles, m + W_TILE_MAP, sizeof(map_tiles));
	frame(m, rom, k, g, PAD_A);
	frame(m, rom, k, g, 0);
	assert(g->map_text_state && m[0xcf13] == 1);
	test_map_dialogue(m, rom, k, g, 1, map_tiles);
	puts("PASS: real D-pad approach and A interaction dispatch Mom's dialogue");
	memcpy(m, saved, GB_STORAGE_SIZE);
	*k = saved_kernel; *g = saved_game;
	port_sync_rom_window(m, m[H_LOADED_ROM_BANK]);
	free(saved);
}

static void test_oak(uint8_t *m, const struct mac_rom *rom)
{
	struct mac_kernel kernel;
	struct mac_game game = {0};
	gb_reset_memory(m, rom);
	kernel_init(&kernel);
	game_boot(&kernel, m, rom, &game);
	unsigned prompts = 0, names = 0, frames;
	struct mac_apu apu;
	apu_init(&apu);
	unsigned audible = 0;
	uint8_t previous = 0;
	unsigned old_naming = 0;
	for (frames = 0; frames < 20000; ++frames) {
		uint8_t pad = 0;
		if (!previous) {
			if (game.phase == MAC_PHASE_TITLE && game.frames_in_phase > 500) pad = PAD_START;
			else if (game.phase == MAC_PHASE_MENU) pad = PAD_A;
			else if (game.phase == MAC_PHASE_NEWGAME) {
				if (game.text.active && game.text.string.waiting) { pad = PAD_A; ++prompts; }
				else if (game.naming == 1 && !game.oak_timer) {
					if (!game.naming_rival && m[0xcc26] == 0) pad = PAD_DOWN;
					else { pad = PAD_A; ++names; }
				} else if (game.naming == 2 && !game.oak_timer) {
					/* Custom rival name A, exercising letter insertion/submission. */
					pad = m[0xcf4b] == 0x50 ? PAD_A : PAD_START;
				}
			}
		}
		frame(m, rom, &kernel, &game, pad);
		if (getenv("POKERED_TEST_TRACE")) {
			if (pad) printf("replay: --pad %u:%u:%02x\n", frames, frames + 1, pad);
			if (game.naming != old_naming) printf("checkpoint: frame=%u naming=%u rival=%u\n", frames, game.naming, game.naming_rival);
		}
		old_naming = game.naming;
		int16_t audio[740];
		apu_render(&apu, m, audio, 739);
		for (unsigned i = 0; i < 739; ++i) audible += audio[i] != 0;
		previous = pad;
		if (game.phase == MAC_PHASE_OVERWORLD) break;
	}
	if (frames == 20000) fprintf(stderr, "Oak stalled: phase %u step %u name %u pointer %02x:%04x sound %u\n",
		game.phase, game.oak_step, game.naming, game.text.bank, game.text.pointer, game.text.sound_wait);
	assert(frames < 20000);
	assert(prompts >= 20 && names == 2);
	assert(audible > 100000);
	assert(memcmp(m + 0xd158, "\x91\x84\x83\x50", 4) == 0); /* RED */
	assert(m[0xd34a] == 0x80 && m[0xd34b] == 0x50); /* A */
	assert(m[0xd35e] == 0x26 && m[0xd361] == 6 && m[0xd362] == 3);
	assert(m[0xd53a] == 1 && m[0xd53b] == 0x14 && m[0xd53c] == 1); /* PC Potion */
	printf("PASS: full Oak dialogue, %u manual prompts, default/custom names -> bedroom (%u frames)\n", prompts, frames);
	/* Same real joypad path used by SDL; stairs and doors must not corrupt
	 * map headers, walk tiles, or immediately warp the player back. */
	const unsigned path[][3] = {{49,81,PAD_UP},{99,163,PAD_RIGHT},
		{189,237,PAD_UP},{349,413,PAD_RIGHT},{439,471,PAD_UP},
		{579,675,PAD_DOWN},{699,779,PAD_LEFT},{819,915,PAD_DOWN}};
	unsigned downstairs = 0, outside = 0;
	for (unsigned f = 0; f < 1049; ++f) {
		uint8_t pad = 0;
		for (unsigned i = 0; i < sizeof(path) / sizeof(*path); ++i)
			if (f >= path[i][0] && f < path[i][1]) pad |= path[i][2];
		frame(m, rom, &kernel, &game, pad);
		downstairs |= m[0xd35e] == 0x25;
		outside |= m[0xd35e] == 0;
		if (f == 500) {
			assert(m[0xd35e] == 0x25 && m[0xd60c] == 1);
			test_talk_to_mom_input(m, rom, &kernel, &game);
			test_map_dialogue(m, rom, &kernel, &game, 1, NULL); /* Mom before starter. */
			test_map_dialogue(m, rom, &kernel, &game, 2, NULL); /* TV from current facing. */
		}
	}
	assert(downstairs && outside && m[0xd35e] == 0);
	assert(game.phase == MAC_PHASE_OVERWORLD && !m[0xcfc5]);
	puts("PASS: walk from bedroom through downstairs to Pallet Town");
	capture_frame(m, "pallet-town");
}

int main(void)
{
	struct mac_rom rom = {0};
	assert(rom_load(&rom, "../pokered.gbc") == 0);
	uint8_t *memory = malloc(GB_STORAGE_SIZE);
	assert(memory);
	test_pictures(memory, &rom);
	test_mode_zero(memory, &rom);
	test_mon_header(memory, &rom);
	test_display_transfers(memory, &rom);
	test_dmg_video(memory, &rom);
	test_audio_fade(memory, &rom);
	test_intro_input(memory, &rom);
	test_text_command_ram_composition(memory, &rom);
	test_oak(memory, &rom);
	free(memory);
	rom_unload(&rom);
	return 0;
}
