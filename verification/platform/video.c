#include "platform.h"

/*
 * Frame-based software model of the DMG PPU:
 *   - BG layer from a 32x32 tilemap with SCX/SCY scroll
 *   - window layer (WX-7, WY)
 *   - 8x8/8x16 sprites from OAM with flips, DMG priority, OBP0/OBP1
 *   - tile data at 0x8000 (unsigned) or 0x8800 (signed) addressing
 *   - BGP/OBP0/OBP1 palette remapping onto the classic DMG greens
 *
 * TODO(PPU-fidelity): mid-frame register writes, pixel-fetch timing and
 * the WX=0/166 edge cases still need independent hardware trace tests.
 * A frame compositor is not generally equivalent to the real PPU.
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
render_layer_row(const uint8_t *memory, uint32_t *rgba, uint8_t *raw_bg, unsigned row,
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
		unsigned color = tile_pixel(memory, tile_addr, xx % 8u, yy % 8u, 0, 0);
		raw_bg[row * GB_SCREEN_W + col] = (uint8_t)color;
		rgba[row * GB_SCREEN_W + col] = shade(bg_pal, color);
	}
}

static void
render_window_row(const uint8_t *memory, uint32_t *rgba, uint8_t *raw_bg, unsigned screen_y,
	int window_x, unsigned window_y, unsigned map_base,
	const uint8_t *bg_pal, int signed_tiles)
{
	unsigned yy = screen_y - window_y;

	for (unsigned screen_x = window_x < 0 ? 0u : (unsigned)window_x;
	    screen_x < GB_SCREEN_W; screen_x++) {
		unsigned xx = (unsigned)((int)screen_x - window_x);
		unsigned tile = memory[map_base + yy / 8u * 32u + xx / 8u];
		unsigned tile_addr = signed_tiles ?
		    (port_u16)(0x9000u + (int)(int8_t)tile * 16) :
		    0x8000u + tile * 16u;

		unsigned color = tile_pixel(memory, tile_addr, xx % 8u, yy % 8u, 0, 0);
		raw_bg[screen_y * GB_SCREEN_W + screen_x] = (uint8_t)color;
		rgba[screen_y * GB_SCREEN_W + screen_x] = shade(bg_pal, color);
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
	uint8_t raw_bg[GB_SCREEN_W * GB_SCREEN_H] = {0};

	if ((lcdc & LCDC_ON) == 0) {
		/* LCD off: blank white panel. */
		for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++)
			rgba[i] = dmg_palette[0];
		return;
	}

	if ((lcdc & LCDC_BG_ON) != 0) {
		for (unsigned row = 0; row < GB_SCREEN_H; row++)
			render_layer_row(memory, rgba, raw_bg, row, bg_map, scx, scy,
			    bg_pal, signed_tiles);
	} else {
		for (unsigned i = 0; i < GB_SCREEN_W * GB_SCREEN_H; i++)
			rgba[i] = dmg_palette[0]; /* DMG LCDC.0 blanks both BG and window. */
	}

	/* The window's visible X origin is WX-7, not WX.  WX values below 7
	 * produce a clipped window beginning at the left edge. */
	if ((lcdc & (LCDC_WINDOW_ON | LCDC_BG_ON)) == (LCDC_WINDOW_ON | LCDC_BG_ON)
	    && wy < GB_SCREEN_H && wx < 167u) {
		int window_x = (int)wx - 7;

		for (unsigned row = wy; row < GB_SCREEN_H; row++)
			render_window_row(memory, rgba, raw_bg, row, window_x, wy,
			    win_map, bg_pal, signed_tiles);
	}

	if ((lcdc & LCDC_SPRITES_ON) == 0)
		return;

	/* DMG selection uses the first ten intersecting Y ranges, even when
	 * their X positions are hidden. Drawing priority is then smaller X,
	 * breaking ties by OAM order. Resolve OBJ/OBJ before OBJ/BG priority.
	 * Reference: gbdev/pandocs src/OAM.md, "Object Priority and Conflicts". */
	unsigned height = (lcdc & LCDC_SPRITE_SIZE_16) ? 16u : 8u;
	for (unsigned sy = 0; sy < GB_SCREEN_H; ++sy) {
		unsigned selected[10], count = 0;
		for (unsigned s = 0; s < 40 && count < 10; ++s) {
			int top = (int)memory[OAM_START + s * 4] - 16;
			if ((int)sy < top || (int)sy >= top + (int)height) continue;
			unsigned i = count++;
			while (i && memory[OAM_START + selected[i - 1] * 4 + 1] > memory[OAM_START + s * 4 + 1]) {
				selected[i] = selected[i - 1]; --i;
			}
			selected[i] = s;
		}
		for (unsigned sx = 0; sx < GB_SCREEN_W; ++sx) {
			for (unsigned i = 0; i < count; ++i) {
				const uint8_t *spr = memory + OAM_START + selected[i] * 4;
				int px = (int)sx - ((int)spr[1] - 8);
				if (px < 0 || px >= 8) continue;
				unsigned py = sy + 16 - spr[0];
				unsigned source_y = spr[3] & 0x40 ? height - 1 - py : py;
				unsigned tile = height == 16 ? (spr[2] & 0xfeu) + source_y / 8 : spr[2];
				unsigned color = tile_pixel(memory, 0x8000 + tile * 16,
				    (unsigned)px, source_y % 8, (spr[3] & 0x20) != 0, 0);
				if (!color) continue;
				unsigned pixel = sy * GB_SCREEN_W + sx;
				if (!(spr[3] & 0x80) || !raw_bg[pixel])
					rgba[pixel] = shade(obp[(spr[3] >> 4) & 1], color);
				break;
			}
		}
	}
}
