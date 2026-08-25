#include "platform.h"

#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * SDL2 shell for the pokered C port on macOS.
 *
 * Default mode runs the game-flow driver (platform/game.c): real
 * DisplayTitleScreen -> MainMenu -> StartNewGame prefix, composed from the
 * ported functions only. --demo keeps the synthetic glue-test screen.
 *
 * Frame loop (59.7275 Hz):
 *   keyboard -> [hJoyInput] -> kernel_vblank() (ported AutoBgMapTransfer /
 *   VBlankCopy* / OAM DMA / port_joypad) -> game_tick() / demo tick ->
 *   video_render() present + apu_render() queued audio.
 *
 * Headless: --smoke runs the same flow without a window and writes a PPM +
 * memory dump with integrity checks.
 */

#define FRAME_RATE_HZ 59.7275
#define SAMPLE_RATE 44100
#define DEMO_SCRATCH 0xD800u /* free WRAM used by the synthetic demo */

/* Glue-owned cursor glyph for the --demo screen: solid block in spare tile
 * $7E ($87E0; empty VRAM past the font in pokered's $8800-mode). */
#define CURSOR_TILE 0x7Eu

void port_init(struct cpu_register_state *state, port_u8 *memory);
void port_place_string(struct cpu_register_state *state, port_u8 *memory);

static const char *demo_lines[] = {
	"POKERED C PORT",
	"MACOS GLUE LAYER",
	"",
	"VIDEO AUDIO INPUT",
	"",
	"DPAD MOVES CURSOR",
	"A OR B TEST TONE",
	"START FLIPS COLORS",
};

/* ASCII -> pokered charmap (subset used by the demo). */
static port_u8
gb_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return (port_u8)(0x80 + (c - 'A'));
	if (c >= 'a' && c <= 'z')
		return (port_u8)(0xA0 + (c - 'a'));
	if (c >= '0' && c <= '9')
		return (port_u8)(0xF6 + (c - '0'));
	switch (c) {
	case ' ':
		return 0x7F;
	case '(':
		return 0x9A;
	case ')':
		return 0x9B;
	case ':':
		return 0x9C;
	case '\'':
		return 0xE0;
	case '-':
		return 0xE3;
	case '?':
		return 0xE6;
	case '!':
		return 0xE7;
	case '.':
		return 0xE8;
	case ',':
		return 0xF4;
	default:
		return 0x7F;
	}
}

static void
boot_demo_screen(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom)
{
	struct cpu_register_state init_regs = { 0 };
	port_u16 off;

	port_init(&init_regs, memory);

	memory[R_BGP] = 0xE4;
	memory[R_OBP0] = 0xE4;
	memory[R_OBP1] = 0xE4;

	memset(memory + 0x8000u + CURSOR_TILE * 16u, 0xFF, 16);

	kernel_copy_video_data_double(kernel, memory, rom, 4, 0x5A80, 0x8800,
	    0x80);

	memset(memory + W_TILE_MAP, 0x7F, 20u * 18u);

	off = 0;
	for (size_t i = 0; i < sizeof(demo_lines) / sizeof(demo_lines[0]);
	     i++) {
		struct cpu_register_state regs = { 0 };
		port_u16 src = DEMO_SCRATCH + off;
		port_u16 dest = W_TILE_MAP + (unsigned)(i + 2) * 20u + 1;

		for (const char *p = demo_lines[i]; *p != '\0'; p++)
			memory[DEMO_SCRATCH + off++] = gb_char(*p);
		memory[DEMO_SCRATCH + off++] = TX_END;

		regs.d = (port_u8)(src >> 8);
		regs.e = (port_u8)(src & 0xFFu);
		regs.h = (port_u8)(dest >> 8);
		regs.l = (port_u8)(dest & 0xFFu);
		port_place_string(&regs, memory);
	}

	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	memory[H_AUTO_BG_TRANSFER_PORTION] = 0;
	memory[H_AUTO_BG_TRANSFER_DEST] = 0x00;
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = 0x98;

	memory[W_SHADOW_OAM + 0] = 80;
	memory[W_SHADOW_OAM + 1] = 88;
	memory[W_SHADOW_OAM + 2] = (uint8_t)CURSOR_TILE;
	memory[W_SHADOW_OAM + 3] = 0x00;
}

static void
demo_tick(uint8_t *memory)
{
	port_u8 held = memory[H_JOYHELD];
	uint8_t *spr = memory + W_SHADOW_OAM;
	int x = spr[1];
	int y = spr[0];

	if ((held & PAD_LEFT) != 0 && x > 12)
		x -= 2;
	if ((held & PAD_RIGHT) != 0 && x < 160)
		x += 2;
	if ((held & PAD_UP) != 0 && y > 12)
		y -= 2;
	if ((held & PAD_DOWN) != 0 && y < 152)
		y += 2;
	spr[0] = (uint8_t)y;
	spr[1] = (uint8_t)x;
	spr[2] = (uint8_t)CURSOR_TILE;
	spr[3] = 0x00;
}

static port_u8
read_pad(const uint8_t *keys)
{
	port_u8 pad = 0;

	if (keys[SDL_SCANCODE_X] || keys[SDL_SCANCODE_K])
		pad |= PAD_A;
	if (keys[SDL_SCANCODE_Z] || keys[SDL_SCANCODE_J])
		pad |= PAD_B;
	if (keys[SDL_SCANCODE_RETURN])
		pad |= PAD_START;
	if (keys[SDL_SCANCODE_BACKSPACE] || keys[SDL_SCANCODE_RSHIFT])
		pad |= PAD_SELECT;
	if (keys[SDL_SCANCODE_RIGHT] || keys[SDL_SCANCODE_D])
		pad |= PAD_RIGHT;
	if (keys[SDL_SCANCODE_LEFT] || keys[SDL_SCANCODE_A])
		pad |= PAD_LEFT;
	if (keys[SDL_SCANCODE_UP] || keys[SDL_SCANCODE_W])
		pad |= PAD_UP;
	if (keys[SDL_SCANCODE_DOWN] || keys[SDL_SCANCODE_S])
		pad |= PAD_DOWN;
	return pad;
}
/* Title logo integrity reference (game.c composes it from bank 4). */
#define SRC_POKEMON_LOGO_GFX 0x5380u
#define V_TITLE_LOGO 0x8800u

struct smoke_checks {
	unsigned ink;
	unsigned audible;
	unsigned logo_mismatches;
	uint32_t rgba_snapshot[GB_SCREEN_W * GB_SCREEN_H];
};

static void
run_smoke_frames(struct mac_kernel *kernel, uint8_t *memory,
	const struct mac_rom *rom, struct mac_game *game, unsigned frames,
	int demo_mode, struct smoke_checks *out)
{
	static uint32_t rgba[GB_SCREEN_W * GB_SCREEN_H];
	static int16_t audio[SAMPLE_RATE / 30];
	struct mac_apu apu;

	apu_init(&apu);
	for (unsigned f = 0; f < frames; f++) {
		memory[H_JOYINPUT] = 0;
		kernel_vblank(kernel, memory, rom);
		if (demo_mode)
			demo_tick(memory);
		else
			game_tick(kernel, memory, rom, game);
		video_render(memory, rgba);
	}
	apu_test_tone(memory, 440, 40);
	apu_render(&apu, memory, audio, (size_t)(SAMPLE_RATE / FRAME_RATE_HZ));

	out->ink = 0;
	out->audible = 0;
	out->logo_mismatches = 0;
	for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++)
		if (rgba[i] != dmg_palette[0])
			out->ink++;
	for (unsigned i = 0; i < SAMPLE_RATE / 30; i++)
		out->audible += audio[i] != 0;

	if (rom->data != NULL &&
	    rom->size >= 4u * 0x4000u + (0x5380u - 0x4000u) + 96u * 16u) {
		const uint8_t *src = rom->data + 4u * 0x4000u +
		    (SRC_POKEMON_LOGO_GFX - 0x4000u);
		unsigned mismatches = 0;

		for (unsigned i = 0; i < 96u * 16u; i++)
			mismatches += memory[V_TITLE_LOGO + i] != src[i];
		out->logo_mismatches = mismatches;
	}

	memcpy(out->rgba_snapshot, rgba, sizeof(rgba));
}

int
main(int argc, char **argv)
{
	struct mac_rom rom = { 0 };
	struct mac_kernel kernel;
	struct mac_game game;
	static uint8_t memory[GB_MEM_SIZE];
	const char *rom_path = "pokered.gbc";
	const char *out_path = "/tmp/pokered_mac_smoke.ppm";
	const char *dump_path = NULL;
	unsigned smoke_frames = 0;
	unsigned run_frames = 0;
	int scale = 4;
	int demo_mode = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--rom") == 0 && i + 1 < argc)
			rom_path = argv[++i];
		else if (strcmp(argv[i], "--scale") == 0 && i + 1 < argc)
			scale = atoi(argv[++i]);
		else if (strcmp(argv[i], "--smoke") == 0)
			smoke_frames = 150;
		else if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc)
			smoke_frames = (unsigned)atoi(argv[++i]);
		else if (strcmp(argv[i], "--run") == 0 && i + 1 < argc)
			run_frames = (unsigned)atoi(argv[++i]);
		else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc)
			dump_path = argv[++i];
		else if (strcmp(argv[i], "--demo") == 0)
			demo_mode = 1;
	}

	if (rom_load(&rom, rom_path) != 0) {
		fprintf(stderr,
		    "pokered-mac: build the ROM first with 'make red' in the "
		    "repo root\n");
		return 1;
	}

	gb_reset_memory(memory, &rom);
	kernel_init(&kernel);

	if (smoke_frames != 0) {
		static struct smoke_checks checks;
		struct mac_apu apu_unused;

		(void)apu_unused;
		memset(&game, 0, sizeof(game));
		if (demo_mode)
			boot_demo_screen(&kernel, memory, &rom);
		else
			game_boot(&kernel, memory, &rom, &game);
		run_smoke_frames(&kernel, memory, &rom, &game, smoke_frames,
		    demo_mode, &checks);

		printf("smoke: selfcheck(5,1)=%06x bgp=%02x\n",
		    checks.rgba_snapshot[1 * GB_SCREEN_W + 5] & 0xFFFFFFu,
		    memory[R_BGP]);
		printf("smoke: logo_byte_mismatches=%u/1536\n",
		    checks.logo_mismatches);
		printf("smoke: frames=%u ink=%u/%d "
		    "audible_samples=%u/%d\n",
		    smoke_frames, checks.ink, GB_SCREEN_W * GB_SCREEN_H,
		    checks.audible, SAMPLE_RATE / 30);
		if (dump_path != NULL) {
			FILE *d = fopen(dump_path, "wb");

			if (d != NULL) {
				fwrite(memory, 1, GB_MEM_SIZE, d);
				fclose(d);
				printf("smoke: memory dumped to %s\n",
				    dump_path);
			}
		}

		FILE *f = fopen(out_path, "wb");

		if (f == NULL)
			return 1;
		fprintf(f, "P6\n%d %d\n255\n", GB_SCREEN_W, GB_SCREEN_H);
		for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++) {
			uint8_t rgb[3] = {
				(uint8_t)(checks.rgba_snapshot[i] >> 16),
				(uint8_t)(checks.rgba_snapshot[i] >> 8),
				(uint8_t)checks.rgba_snapshot[i]
			};
			fwrite(rgb, 1, 3, f);
		}
		fclose(f);
		printf("smoke: frame written to %s\n", out_path);
		rom_unload(&rom);
		return 0;
	}

	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) != 0) {
		fprintf(stderr, "pokered-mac: SDL_Init: %s\n", SDL_GetError());
		rom_unload(&rom);
		return 1;
	}

	char title[128];
	snprintf(title, sizeof(title), "pokered-mac (%s)", rom_path);
	SDL_Window *window = SDL_CreateWindow(title, SDL_WINDOWPOS_CENTERED,
	    SDL_WINDOWPOS_CENTERED, GB_SCREEN_W * scale, GB_SCREEN_H * scale,
	    SDL_WINDOW_RESIZABLE);
	SDL_Renderer *renderer = SDL_CreateRenderer(window, -1,
	    SDL_RENDERER_ACCELERATED);
	if (renderer == NULL)
		renderer = SDL_CreateRenderer(window, -1, 0);
	SDL_Texture *texture = SDL_CreateTexture(renderer,
	    SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, GB_SCREEN_W,
	    GB_SCREEN_H);

	SDL_AudioSpec want = { 0 }, have;
	want.freq = SAMPLE_RATE;
	want.format = AUDIO_S16LSB;
	want.channels = 1;
	want.samples = 1024;
	SDL_AudioDeviceID audio_dev =
	    SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
	struct mac_apu apu;
	apu_init(&apu);
	if (audio_dev != 0)
		SDL_PauseAudioDevice(audio_dev, 0);

	static uint32_t rgba[GB_SCREEN_W * GB_SCREEN_H];
	const size_t samples_per_frame =
	    (size_t)(SAMPLE_RATE / FRAME_RATE_HZ + 0.5);
	static int16_t frame_audio[SAMPLE_RATE / 30];

	memset(&game, 0, sizeof(game));
	if (demo_mode)
		boot_demo_screen(&kernel, memory, &rom);
	else
		game_boot(&kernel, memory, &rom, &game);

	Uint64 tick0 = SDL_GetPerformanceCounter();
	const double perf_freq = (double)SDL_GetPerformanceFrequency();
	unsigned frame_no = 0;
	int running = 1;
	while (running) {
		SDL_Event ev;
		while (SDL_PollEvent(&ev)) {
			if (ev.type == SDL_QUIT ||
			    (ev.type == SDL_KEYDOWN &&
				ev.key.keysym.sym == SDLK_ESCAPE))
				running = 0;
		}

		const Uint8 *keys = SDL_GetKeyboardState(NULL);
		memory[H_JOYINPUT] = read_pad(keys);

		kernel_vblank(&kernel, memory, &rom);

		if (demo_mode) {
			port_u8 pressed = memory[H_JOYPRESSED];

			if ((pressed & PAD_A) != 0)
				apu_test_tone(memory, 1046, 180);
			if ((pressed & PAD_B) != 0)
				apu_test_tone(memory, 659, 180);
			if ((pressed & PAD_START) != 0)
				memory[R_BGP] ^= 0xFFu;
			demo_tick(memory);
		} else {
			game_tick(&kernel, memory, &rom, &game);
		}

		video_render(memory, rgba);
		SDL_UpdateTexture(texture, NULL, rgba, GB_SCREEN_W * 4);
		SDL_RenderClear(renderer);
		SDL_RenderCopy(renderer, texture, NULL, NULL);
		SDL_RenderPresent(renderer);

		apu_render(&apu, memory, frame_audio, samples_per_frame);
		if (audio_dev != 0)
			SDL_QueueAudio(audio_dev, frame_audio,
			    (Uint32)(samples_per_frame * sizeof(int16_t)));

		frame_no++;
		if (run_frames != 0 && frame_no >= run_frames)
			running = 0;

		double target = (double)frame_no / FRAME_RATE_HZ * 1e6;
		double now = (double)(SDL_GetPerformanceCounter() - tick0) /
		    perf_freq * 1e6;
		if (target > now)
			SDL_Delay((Uint32)((target - now) / 1000.0));
	}

	if (audio_dev != 0)
		SDL_CloseAudioDevice(audio_dev);
	SDL_DestroyTexture(texture);
	SDL_DestroyRenderer(renderer);
	SDL_DestroyWindow(window);
	SDL_Quit();
	rom_unload(&rom);
	printf("pokered-mac: ran %u frames\n", frame_no);
	return 0;
}
