#include "platform.h"

/*
 * Software model of the DMG PPU, sufficient for every screen state the
 * current ports can produce:
 *   - BG layer from a 32x32 tilemap with SCX/SCY scroll
 *   - window layer (WX-7, WY)
 *   - 8x8/8x16 sprites from OAM with flips, DMG priority, OBP0/OBP1
 *   - tile data at 0x8000 (unsigned) or 0x8800 (signed) addressing
 *   - BGP/OBP0/OBP1 palette remapping onto the classic DMG greens
 *
 * The real PPU renders scanline-by-scanline mid-frame; games only observe
 * whole frames through VBlank, so a per-frame compositor is equivalent for
 * this port.
 */

const uint32_t dmg_palette[4] = {
	0xFF9BBC0Fu, /* lightest green */
	0xFF8BAC0Fu,
	0xFF306230u,
	0xFF0F380Fu, /* darkest green */
};

static uint32_t
shade(const uint8_t *pal, unsigned color_index)
{
	/* BGP/OBPx map each 2bpp color index to a palette entry in its own
	 * 2-bit field: entry = (reg >> (index*2)) & 3. */
	unsigned entry = (*pal >> (color_index * 2u)) & 3u;

	return dmg_palette[entry];
}

static unsigned
tile_pixel(const uint8_t *memory, unsigned tile_addr, unsigned x, unsigned y,
	int flip_x, int flip_y)
{
	unsigned row = flip_y ? 7u - y : y;
	unsigned col = flip_x ? 7u - x : x;
	const uint8_t *line = memory + tile_addr + row * 2u;
	unsigned lo = (line[0] >> (7u - col)) & 1u;
	unsigned hi = (line[1] >> (7u - col)) & 1u;

	return (hi << 1) | lo;
}

static void
render_layer_row(const uint8_t *memory, uint32_t *rgba, unsigned row,
	unsigned map_base, unsigned scx, unsigned scy,
	const uint8_t *bg_pal, int signed_tiles)
{
	for (unsigned col = 0; col < GB_SCREEN_W; col++) {
		unsigned xx = (scx + col) & 255u; /* wraps at 256 px */
		unsigned yy = (scy + row) & 255u;
		const uint8_t *entry =
		    memory + map_base + yy / 8u * 32u + xx / 8u;
		unsigned tile = *entry;
		unsigned tile_addr;

		/* LCDC.4=0 ("$8800 method"): the map byte is a signed index
		 * from base $9000, spanning $8800-$97F0; pokered boots this
		 * way, so text codes $80+ land on the font at $8800.
		 * LCDC.4=1: unsigned indices over $8000-$8FFF. */
		tile_addr = signed_tiles ?
		    (port_u16)(0x9000u + (int)(int8_t)tile * 16) :
		    0x8000u + tile * 16u;
		rgba[row * GB_SCREEN_W + col] = shade(bg_pal,
		    tile_pixel(memory, tile_addr, xx % 8u, yy % 8u, 0, 0));
	}
}

static void
render_window_row(const uint8_t *memory, uint32_t *rgba, unsigned screen_y,
	unsigned window_x, unsigned window_y, unsigned map_base,
	const uint8_t *bg_pal, int signed_tiles)
{
	unsigned yy = screen_y - window_y;

	for (unsigned screen_x = window_x; screen_x < GB_SCREEN_W; screen_x++) {
		unsigned xx = screen_x - window_x;
		unsigned tile = memory[map_base + yy / 8u * 32u + xx / 8u];
		unsigned tile_addr = signed_tiles ?
		    (port_u16)(0x9000u + (int)(int8_t)tile * 16) :
		    0x8000u + tile * 16u;

		rgba[screen_y * GB_SCREEN_W + screen_x] = shade(bg_pal,
		    tile_pixel(memory, tile_addr, xx % 8u, yy % 8u, 0, 0));
	}
}

void
video_render(const uint8_t *memory, uint32_t *rgba)
{
	uint8_t lcdc = memory[R_LCDC];
	const uint8_t *bg_pal = memory + R_BGP;
	const uint8_t *obp[2] = { memory + R_OBP0, memory + R_OBP1 };
	unsigned scx = memory[R_SCX];
	unsigned scy = memory[R_SCY];
	unsigned wx = memory[R_WX];
	unsigned wy = memory[R_WY];
	int signed_tiles = (lcdc & LCDC_TILEDATA_8000) == 0;
	unsigned bg_map = (lcdc & LCDC_BG_MAP_9C00) ? 0x9C00u : 0x9800u;
	unsigned win_map = (lcdc & LCDC_WINDOW_MAP_9C00) ? 0x9C00u : 0x9800u;

	if ((lcdc & LCDC_ON) == 0) {
		/* LCD off: blank white panel. */
		for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++)
			rgba[i] = dmg_palette[0];
		return;
	}

	if ((lcdc & LCDC_BG_ON) != 0) {
		for (unsigned row = 0; row < GB_SCREEN_H; row++)
			render_layer_row(memory, rgba, row, bg_map, scx, scy,
			    bg_pal, signed_tiles);
	} else {
		for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++)
			rgba[i] = shade(bg_pal, 0);
	}

	/* The window's visible X origin is WX-7, not WX.  WX values below 7
	 * produce a clipped window beginning at the left edge. */
	if ((lcdc & LCDC_WINDOW_ON) != 0 && wy < GB_SCREEN_H && wx < 167u) {
		unsigned window_x = wx < 7u ? 0u : wx - 7u;

		for (unsigned row = wy; row < GB_SCREEN_H; row++)
			render_window_row(memory, rgba, row, window_x, wy,
			    win_map, bg_pal, signed_tiles);
	}

	if ((lcdc & LCDC_SPRITES_ON) == 0)
		return;

	/* Sprites are rendered last-to-first so lower OAM entries win. */
	for (int s = 39; s >= 0; s--) {
		const uint8_t *spr = memory + OAM_START + (unsigned)s * 4u;
		unsigned y = spr[0];
		unsigned x = spr[1];
		unsigned tile = spr[2];
		unsigned attr = spr[3];
		const uint8_t *pal = obp[(attr >> 4) & 1u];
		int flip_x = (attr & 0x20) != 0;
		int flip_y = (attr & 0x40) != 0;
		int behind_bg = (attr & 0x80) != 0;
		unsigned height = (lcdc & LCDC_SPRITE_SIZE_16) ? 16u : 8u;

		if (x == 0 || x >= 168u || y == 0 || y >= 160u)
			continue; /* off-screen / hidden */

		for (unsigned py = 0; py < height; py++) {
			int sy = (int)y - 16 + (int)py;
			unsigned source_y = flip_y ? height - 1u - py : py;
			unsigned source_tile = height == 16u ?
			    (tile & 0xFEu) + source_y / 8u : tile;

			if (sy < 0 || sy >= GB_SCREEN_H)
				continue;
			for (unsigned px = 0; px < 8; px++) {
				int sx = (int)x - 8 + (int)px;
				unsigned color;

				if (sx < 0 || sx >= GB_SCREEN_W)
					continue;
				color = tile_pixel(memory,
				    0x8000u + source_tile * 16u, px,
				    source_y % 8u, flip_x, 0);
				if (color == 0)
					continue; /* sprite transparency */
				if (behind_bg &&
				    rgba[(unsigned)sy * GB_SCREEN_W +
					(unsigned)sx] !=
					shade(bg_pal, 0))
					continue; /* BG has priority */
				rgba[(unsigned)sy * GB_SCREEN_W +
				    (unsigned)sx] = shade(pal, color);
			}
		}
	}
}
