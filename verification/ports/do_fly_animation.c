#include "port_state.h"

#define USE_LIST 0xcd3du
#define COUNTER 0xcd3eu
#define BIRD_IMAGE 0xcd3fu
#define PLAYER_IMAGE 0xc102u
#define PLAYER_Y 0xc104u
#define PLAYER_X 0xc106u

void port_delay3(struct cpu_register_state *, port_u8 *);

static void cp_a(struct cpu_register_state *r, port_u8 value)
{
	port_u8 old = r->a;
	r->f = PORT_FLAG_N | (old == value ? PORT_FLAG_Z : 0)
		| ((old & 15) < (value & 15) ? PORT_FLAG_H : 0)
		| (old < value ? PORT_FLAG_C : 0);
}

static void dec_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	r->a--;
	r->f = (r->f & PORT_FLAG_C) | PORT_FLAG_N
		| (r->a == 0 ? PORT_FLAG_Z : 0)
		| ((old & 15) == 0 ? PORT_FLAG_H : 0);
}

/* Port of DoFlyAnimation in engine/overworld/player_animations.asm. */
__attribute__((noinline, used)) void
port_do_fly_animation(struct cpu_register_state *r, port_u8 *memory)
{
	for (;;) {
		port_u16 de;

		r->a = memory[BIRD_IMAGE] ^ 1;
		r->f = r->a == 0 ? PORT_FLAG_Z : 0;
		memory[BIRD_IMAGE] = r->a;
		memory[PLAYER_IMAGE] = r->a;
		port_delay3(r, memory);
		r->a = memory[USE_LIST];
		cp_a(r, 0xff);
		if (!(r->f & PORT_FLAG_Z)) {
			de = (port_u16)(((port_u16)r->d << 8) | r->e);
			r->h = (port_u8)(PLAYER_Y >> 8);
			r->l = (port_u8)PLAYER_Y;
			r->a = memory[de++];
			memory[((port_u16)r->h << 8) | r->l++] = r->a;
			r->l++;
			r->a = memory[de++];
			memory[PLAYER_X] = r->a;
			r->d = (port_u8)(de >> 8);
			r->e = (port_u8)de;
		}
		r->a = memory[COUNTER];
		dec_a(r);
		memory[COUNTER] = r->a;
		if (r->f & PORT_FLAG_Z)
			return;
	}
}
