#include "port_state.h"

#define BANK_RED_SPRITE 5u
#define NUM_TILES 0x0cu

/* Port of LoadPlayerSpriteGraphicsCommon (home/overworld.asm).
 *
 * Copies the player sprite (source in DE, destination in HL) and a second
 * block offset by $c0 in the source and $800 in the destination, $0c tiles
 * each from BANK(RedSprite), via CopyVideoData (ported). DE/HL are inputs set
 * by the caller. */
extern void port_copy_video_data(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_load_player_sprite_graphics_common(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 de = (port_u16)(((port_u16)state->d << 8) | state->e);
	port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);

	/* first copy: ld b, BANK(RedSprite); lb c, $0c; call CopyVideoData */
	state->b = BANK_RED_SPRITE;
	state->c = NUM_TILES;
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)(de & 0xffu);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xffu);
	port_copy_video_data(state, memory);

	/* second copy: de += $c0, hl += $800 (set bit 3 of h) */
	de += 0xc0u;
	hl += 0x800u;
	state->b = BANK_RED_SPRITE;
	state->c = NUM_TILES;
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)(de & 0xffu);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xffu);
	port_copy_video_data(state, memory);
}
