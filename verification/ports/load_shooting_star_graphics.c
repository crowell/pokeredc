#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *, port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);

#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define H_LOADED_ROM_BANK 0xffb8u
#define H_ROM_BANK_TEMP 0xff8bu
#define R_ROMB 0x2000u
#define H_VBLANK_COPY_SOURCE 0xffc7u
#define H_VBLANK_COPY_DEST 0xffc9u
#define H_VBLANK_COPY_SIZE 0xffc6u
#define R_OBP0 0xff48u
#define R_OBP1 0xff49u
#define MOVE_ANIMATION_TILES1 0x46eeu
#define FALLING_STAR 0x4190u
#define GAME_FREAK_LOGO_OAM_DATA 0x4140u
#define GAME_FREAK_SHOOTING_STAR_OAM_DATA 0x4180u
#define VCHARS1 0x8800u
#define W_SHADOW_OAM 0xc300u
#define W_SHADOW_OAM_SPRITE24 (W_SHADOW_OAM + 24u * 4u)
#define MOVE_ANIMATION_TILES1_BANK 0x1eu
#define FALLING_STAR_BANK 0x1cu
#define GAME_FREAK_LOGO_OAM_DATA_SIZE 0x40u
#define GAME_FREAK_SHOOTING_STAR_OAM_DATA_SIZE 0x10u
#define TILE_SIZE 0x10u

static void
copy_video(struct cpu_register_state *state, port_u8 *memory,
	port_u16 source, port_u16 destination, port_u8 bank, port_u8 tiles)
{
	state->d = (port_u8)(source >> 8);
	state->e = (port_u8)source;
	state->h = (port_u8)(destination >> 8);
	state->l = (port_u8)destination;
	state->b = bank;
	state->c = tiles;
	port_copy_video_data(state, memory);
}

static void
copy_oam(struct cpu_register_state *state, port_u8 *memory,
	port_u16 source, port_u16 destination, port_u16 size)
{
	state->h = (port_u8)(source >> 8);
	state->l = (port_u8)source;
	state->d = (port_u8)(destination >> 8);
	state->e = (port_u8)destination;
	state->b = (port_u8)(size >> 8);
	state->c = (port_u8)size;
	port_copy_data(state, memory);
}

/* Port of LoadShootingStarGraphics in engine/movie/splash.asm. */
__attribute__((noinline, used)) void
port_load_shooting_star_graphics(struct cpu_register_state *state,
	port_u8 *memory)
{
	memory[R_OBP0] = 0xf9u;
	state->a = memory[R_OBP0];
	memory[R_OBP1] = 0xa4u;
	state->a = memory[R_OBP1];

	copy_video(state, memory, MOVE_ANIMATION_TILES1 + 3u * TILE_SIZE,
		VCHARS1 + 0x20u * TILE_SIZE, MOVE_ANIMATION_TILES1_BANK, 1);
	copy_video(state, memory, MOVE_ANIMATION_TILES1 + 19u * TILE_SIZE,
		VCHARS1 + 0x21u * TILE_SIZE, MOVE_ANIMATION_TILES1_BANK, 1);
	copy_video(state, memory, FALLING_STAR,
		VCHARS1 + 0x22u * TILE_SIZE, FALLING_STAR_BANK, 1);
	copy_oam(state, memory, GAME_FREAK_LOGO_OAM_DATA,
		W_SHADOW_OAM_SPRITE24, GAME_FREAK_LOGO_OAM_DATA_SIZE);
	copy_oam(state, memory, GAME_FREAK_SHOOTING_STAR_OAM_DATA,
		W_SHADOW_OAM, GAME_FREAK_SHOOTING_STAR_OAM_DATA_SIZE);
}
