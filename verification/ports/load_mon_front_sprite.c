#include "port_state.h"

port_u8 port_uncompress_sprite_data(struct cpu_register_state *, port_u8 *);
void port_load_uncompressed_sprite_data(struct cpu_register_state *, port_u8 *);

/* UncompressMonSprite / LoadMonFrontSprite, home/pics.asm. Unlike the
 * historical LoadFrontSpriteByMonIndex snapshot, this executes the actual
 * data-transfer continuations. TODO(proof): composed SM83 equivalence. */
__attribute__((noinline, used)) void
port_load_mon_front_sprite(struct cpu_register_state *r, port_u8 *m)
{
	port_u8 saved_d = r->d, saved_e = r->e;
	port_u8 species = m[0xcf91];
	m[0xd0ab] = m[0xd0c3];
	m[0xd0ac] = m[0xd0c4];
	r->a = species == 0x15 ? 1 : species == 0xb6 ? 0x0b :
		species < 0x1f ? 9 : species < 0x4a ? 0x0a :
		species < 0x74 ? 0x0b : species < 0x99 ? 0x0c : 0x0d;
	if (!port_uncompress_sprite_data(r, m)) return;
	r->a = r->c = m[0xd0c2];
	r->d = saved_d;
	r->e = saved_e;
	port_load_uncompressed_sprite_data(r, m);
}
