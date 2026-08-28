#include "port_state.h"

#define TILE_SIZE 16u
#define V_CHARS1_TILE_7C 0x8fc0u

void port_load_smoke_tile(struct cpu_register_state *, port_u8 *);

static void
add_hl(struct cpu_register_state *r, port_u16 value)
{
	port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u32 wide = (port_u32)hl + value;
	port_u8 flags = (port_u8)(r->f & PORT_FLAG_Z);

	if ((hl & 0x0fffu) + value > 0x0fffu)
		flags |= PORT_FLAG_H;
	if (wide > 0xffffu)
		flags |= PORT_FLAG_C;
	r->h = (port_u8)(wide >> 8);
	r->l = (port_u8)wide;
	r->f = flags;
}

static void
dec_c(struct cpu_register_state *r)
{
	port_u8 before = r->c;
	port_u8 flags = (port_u8)(r->f & PORT_FLAG_C);

	r->c = (port_u8)(before - 1u);
	flags |= PORT_FLAG_N;
	if (r->c == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		flags |= PORT_FLAG_H;
	r->f = flags;
}

/* Port of LoadSmokeTileFourTimes in engine/overworld/dust_smoke.asm. */
__attribute__((noinline, used)) void
port_load_smoke_tile_four_times(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 saved_b = r->b;
	port_u8 saved_c;
	port_u8 saved_h;
	port_u8 saved_l;

	r->h = (port_u8)(V_CHARS1_TILE_7C >> 8);
	r->l = (port_u8)V_CHARS1_TILE_7C;
	r->c = 4u;
	do {
		saved_c = r->c;
		saved_h = r->h;
		saved_l = r->l;
		port_load_smoke_tile(r, memory);
		r->h = saved_h;
		r->l = saved_l;
		r->b = 0;
		r->c = 0x10u;
		add_hl(r, TILE_SIZE);
		r->b = saved_b;
		r->c = saved_c;
		dec_c(r);
	} while (r->c != 0);
}
