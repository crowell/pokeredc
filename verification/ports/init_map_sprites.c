#include "port_state.h"

/* Port of InitMapSprites in engine/overworld/map_sprites.asm. */

#define W_SPRITE_PLAYER_STATE_DATA1_PICTURE_ID 0xc100u
#define W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID 0xc20du
#define SPRITE_STATE_LENGTH 16u
#define NUM_SPRITE_STATE_STRUCTS 16u

void port_init_outside_map_sprites(struct cpu_register_state *, port_u8 *);
void port_load_map_sprite_tile_patterns(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_init_map_sprites(struct cpu_register_state *r, port_u8 *memory)
{
	port_init_outside_map_sprites(r, memory);
	if ((r->f & PORT_FLAG_C) != 0)
		return;

	/* Copy each data1 picture ID into the corresponding data2 temporary
	 * picture-ID slot.  As in the SM83 routine, the low-byte strides wrap
	 * without carrying into H/D. */
	for (unsigned i = 0; i < NUM_SPRITE_STATE_STRUCTS; ++i) {
		port_u16 source = (port_u16)(W_SPRITE_PLAYER_STATE_DATA1_PICTURE_ID +
			i * SPRITE_STATE_LENGTH);
		port_u16 destination =
			(port_u16)(W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID +
			i * SPRITE_STATE_LENGTH);
		r->a = memory[source];
		memory[destination] = r->a;
	}
	r->h = 0xc1;
	r->l = 0x00;
	r->d = 0xc2;
	r->e = 0x0d;
	r->a = 0;
	r->f = PORT_FLAG_Z;

	/* This is the assembly fall-through into the complete local loader. */
	port_load_map_sprite_tile_patterns(r, memory);
}
