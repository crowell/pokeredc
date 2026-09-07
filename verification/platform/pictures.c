#include "platform.h"

void port_load_mon_front_sprite(struct cpu_register_state *, port_u8 *);
void port_copy_uncompressed_pic_to_tilemap(struct uncompressed_pic_copy_state *);
void port_intro_display_pic_centered_or_upper_right(
	struct uncompressed_pic_copy_state *, port_u8 *);

/* Runtime continuation of LoadFrontSpriteByMonIndex; its legacy proof
 * observes the calls but does not execute their sprite writes. TODO(proof):
 * extend that contract to the complete bank-aware memory transition. */
void picture_mon(uint8_t *m, unsigned tilemap, int flipped)
{
	unsigned species = m[0xcf91];
	if (!species || species > 190 ||
	    !m[PORT_ROM_BACKING_BASE + 16 * 0x4000 + 0x1024 + species - 1]) {
		m[0xcf91] = 1; /* Original Rhydon trap. */
		return;
	}
	struct cpu_register_state r = {.d = 0x90};
	m[0xd0aa] = flipped != 0;
	port_load_mon_front_sprite(&r, m);
	struct uncompressed_pic_copy_state copy = {0};
	copy.predef_h = (port_u8)(tilemap >> 8);
	copy.predef_l = (port_u8)tilemap;
	copy.sprite_flipped = m[0xd0aa];
	m[0xffe1] = 0;
	port_copy_uncompressed_pic_to_tilemap(&copy);
	for (unsigned x = 0; x < 7; ++x)
		for (unsigned y = 0; y < 7; ++y)
			m[tilemap + (flipped ? 6 - x : x) + y * 20] = copy.writes[x * 7 + y];
	m[0xd0aa] = 0;
}

void picture_trainer(uint8_t *m, unsigned bank, unsigned source)
{
	struct uncompressed_pic_copy_state copy = {0};
	copy.registers.b = (port_u8)bank;
	copy.registers.d = (port_u8)(source >> 8);
	copy.registers.e = (port_u8)source;
	port_intro_display_pic_centered_or_upper_right(&copy, m);
}
