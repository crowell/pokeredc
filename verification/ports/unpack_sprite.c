#include "port_state.h"

#define S_SPRITE_BUFFER1 0xa188u
#define S_SPRITE_BUFFER2 0xa310u
#define W_SPRITE_UNPACK_MODE 0xd0a9u

void port_sprite_differential_decode(struct cpu_register_state *, port_u8 *);
void port_xor_sprite_chunks(struct cpu_register_state *, port_u8 *);
void port_unpack_sprite_mode2(struct cpu_register_state *, port_u8 *);

static void
unpack_sprite_cp(struct cpu_register_state *state, port_u8 value)
{
	port_u8 left = state->a;

	state->f = PORT_FLAG_N;
	if (left == value)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		state->f |= PORT_FLAG_H;
	if (left < value)
		state->f |= PORT_FLAG_C;
}

/* Port of UnpackSprite in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_unpack_sprite(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = memory[W_SPRITE_UNPACK_MODE];
	unpack_sprite_cp(state, 2);
	if (state->a == 2) {
		port_unpack_sprite_mode2(state, memory);
		return;
	}
	state->f = (port_u8)(PORT_FLAG_H |
		(state->a == 0 ? PORT_FLAG_Z : 0));
	if (state->a != 0) {
		port_xor_sprite_chunks(state, memory);
		return;
	}
	state->h = (port_u8)(S_SPRITE_BUFFER1 >> 8);
	state->l = (port_u8)S_SPRITE_BUFFER1;
	port_sprite_differential_decode(state, memory);
	state->h = (port_u8)(S_SPRITE_BUFFER2 >> 8);
	state->l = (port_u8)S_SPRITE_BUFFER2;
	port_sprite_differential_decode(state, memory);
}
