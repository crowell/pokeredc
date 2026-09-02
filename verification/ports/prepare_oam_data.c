#include "port_state.h"

#define W_UPDATE_SPRITES_ENABLED 0xcfcbU
#define W_SPRITE_STATE_DATA1 0xc100U
#define W_SPRITE_STATE_DATA2 0xc200U
#define W_SHADOW_OAM 0xc300U
#define W_SAVED_IMAGE 0xd5cdU
#define W_MOVEMENT_FLAGS 0xd736U
#define H_SPRITE_OFFSET 0xff8fU
#define H_OAM_OFFSET 0xff90U
#define H_SCREEN_X 0xff91U
#define H_SCREEN_Y 0xff92U
#define H_PRIORITY 0xff94U
#define SPRITE_TABLE 0x4000U
#define SHADOW_OAM_SPRITE36 0xc390U
#define SHADOW_OAM_END 0xc3a0U

void port_hide_sprites(struct clear_sprites_state *);
void port_get_sprite_screen_xy_memory(struct cpu_register_state *, port_u8 *);

static void
dec8(struct cpu_register_state *r)
{
	port_u8 before = r->a;
	r->a = (port_u8)(before - 1u);
	r->f = (port_u8)(r->f & PORT_FLAG_C);
	r->f |= PORT_FLAG_N;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fU) == 0)
		r->f |= PORT_FLAG_H;
}

static void
cp8(struct cpu_register_state *r, port_u8 right)
{
	port_u8 left = r->a;
	r->f = PORT_FLAG_N;
	if (left == right)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fU) < (right & 0x0fU))
		r->f |= PORT_FLAG_H;
	if (left < right)
		r->f |= PORT_FLAG_C;
}

static void
hide_all(struct cpu_register_state *r, port_u8 *memory)
{
	struct clear_sprites_state state = {0};
	port_u16 i;

	state.registers = *r;
	for (i = 0; i < 160u; ++i)
		state.oam[i] = memory[W_SHADOW_OAM + i];
	port_hide_sprites(&state);
	*r = state.registers;
	for (i = 0; i < 160u; ++i)
		memory[W_SHADOW_OAM + i] = state.oam[i];
}

/* Port of PrepareOAMData in engine/gfx/sprite_oam.asm. */
__attribute__((noinline, used)) void
port_prepare_oam_data(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 enabled = memory[W_UPDATE_SPRITES_ENABLED];
	port_u8 offset;
	port_u8 oam_offset;
	port_u8 clear_end;

	r->a = enabled;
	dec8(r);
	if (r->a != 0) {
		cp8(r, 0xffu);
		if (r->a != 0xffu)
			return;
		memory[W_UPDATE_SPRITES_ENABLED] = r->a;
		hide_all(r, memory);
		return;
	}

	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[H_OAM_OFFSET] = 0;
	oam_offset = 0;
	for (offset = 0; ; offset = (port_u8)(offset + 0x10u)) {
		port_u8 picture = memory[W_SPRITE_STATE_DATA1 + offset];
		port_u8 image;
		port_u8 table_index;
		port_u16 entry;
		port_u16 pattern;
		port_u16 coordinate;

		memory[H_SPRITE_OFFSET] = offset;
		r->d = 0xc1;
		r->e = offset;
		r->a = picture;
		if (picture != 0) {
			image = memory[W_SPRITE_STATE_DATA1 + offset + 2u];
			memory[W_SAVED_IMAGE] = image;
			/* The two image-index loads in the assembly leave E at slot + 2
			 * before the GetSpriteScreenXY call. */
			r->e = (port_u8)(offset + 2u);
			if (image == 0xffu) {
				port_get_sprite_screen_xy_memory(r, memory);
			} else {
				table_index = (port_u8)(image & 0x0fu);
				if (image >= 0xa0u)
					table_index = (port_u8)(table_index + 0x10u);
				r->l = table_index;
				memory[H_PRIORITY] =
					(port_u8)(memory[W_SPRITE_STATE_DATA2 + offset + 7u] & 0x80u);
				entry = (port_u16)(SPRITE_TABLE + (port_u16)table_index * 4u);
				pattern = (port_u16)(memory[entry] |
					((port_u16)memory[entry + 1u] << 8));
				coordinate = (port_u16)(memory[entry + 2u] |
					((port_u16)memory[entry + 3u] << 8));
				r->b = (port_u8)(pattern >> 8);
				r->c = (port_u8)pattern;
				r->h = (port_u8)(coordinate >> 8);
				r->l = (port_u8)coordinate;
				port_get_sprite_screen_xy_memory(r, memory);
				oam_offset = memory[H_OAM_OFFSET];
				for (;;) {
					port_u8 yoff = memory[coordinate++];
					port_u8 xoff = memory[coordinate++];
					port_u8 tile = memory[pattern++];
					port_u8 sprite_number =
						(port_u8)((memory[W_SAVED_IMAGE] >> 4) & 0x0fu);
					port_u8 attr = memory[coordinate];
					port_u8 tile_offset;

					memory[W_SHADOW_OAM + oam_offset] =
						(port_u8)(memory[H_SCREEN_Y] + 0x10u + yoff);
					memory[W_SHADOW_OAM + oam_offset + 1u] =
						(port_u8)(memory[H_SCREEN_X] + 8u + xoff);
					tile_offset = sprite_number == 0x0bu ? 0x7cu :
						(port_u8)(sprite_number * 12u);
					memory[W_SHADOW_OAM + oam_offset + 2u] =
						(port_u8)(tile + tile_offset);
					r->b = (port_u8)(pattern >> 8);
					r->c = (port_u8)pattern;
					if ((attr & 0x02u) != 0)
						attr |= memory[H_PRIORITY];
					memory[W_SHADOW_OAM + oam_offset + 3u] = attr;
					oam_offset = (port_u8)(oam_offset + 4u);
					coordinate++;
					if ((attr & 0x01u) != 0)
						break;
				}
				memory[H_OAM_OFFSET] = oam_offset;
			}
		}
		if (offset == 0xf0u)
			break;
	}

	oam_offset = memory[H_OAM_OFFSET];
	r->l = oam_offset;
	r->h = 0xc3;
	r->d = 0;
	r->e = 4;
	r->b = 0xa0u;
	r->a = memory[W_MOVEMENT_FLAGS];
	clear_end = (r->a & 0x40u) != 0 ? 0x90u : 0xa0u;
	r->a = clear_end;
	while (r->l != clear_end) {
		memory[W_SHADOW_OAM + r->l] = 0xa0u;
		r->l = (port_u8)(r->l + 4u);
	}
	cp8(r, r->l);
}
