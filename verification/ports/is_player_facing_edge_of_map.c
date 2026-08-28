#include "port_state.h"

#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_CUR_MAP_HEIGHT 0xd368u
#define W_CUR_MAP_WIDTH 0xd369u
#define W_FACING 0xc109u

static void
set_cp_flags(struct cpu_register_state *r, port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	r->f = PORT_FLAG_N;
	if (result == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < right)
		r->f |= PORT_FLAG_C;
}

static void
set_and_flags(struct cpu_register_state *r, port_u8 value)
{
	r->f = value == 0u ? PORT_FLAG_Z : 0;
}

/* Port of IsPlayerFacingEdgeOfMap in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) port_u8
port_is_player_facing_edge_of_map(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 saved_hl = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u16 saved_de = (port_u16)(((port_u16)r->d << 8) | r->e);
	port_u8 saved_b = r->b;
	port_u8 saved_c = r->c;
	port_u8 facing = memory[W_FACING];
	port_u8 direction = (port_u8)(facing >> 1);
	port_u8 index = (port_u8)(direction >> 1);
	port_u8 coordinate;
	port_u8 limit;
	port_u8 edge;

	/* The assembly indexes a four-entry pointer table by facing / 2. */
	r->c = direction;
	r->b = 0;
	r->h = 0;
	r->l = (port_u8)(0x00u + direction * 2u);
	if (index == 0u) {
		coordinate = memory[W_Y_COORD];
		limit = (port_u8)(memory[W_CUR_MAP_HEIGHT] * 2u - 1u);
		r->a = limit;
		set_cp_flags(r, limit, coordinate);
		if ((r->f & PORT_FLAG_Z) != 0u)
			r->f = PORT_FLAG_Z | PORT_FLAG_C;
		else
			set_and_flags(r, limit);
	} else if (index == 1u) {
		coordinate = memory[W_Y_COORD];
		r->a = coordinate;
		/* AND A: Z iff the coordinate is zero, with N/H/C clear. */
		r->f = coordinate == 0u ? (PORT_FLAG_Z | PORT_FLAG_C) : 0;
	} else if (index == 2u) {
		coordinate = memory[W_X_COORD];
		r->a = coordinate;
		r->f = coordinate == 0u ? (PORT_FLAG_Z | PORT_FLAG_C) : 0;
	} else {
		coordinate = memory[W_X_COORD];
		limit = (port_u8)(memory[W_CUR_MAP_WIDTH] * 2u - 1u);
		r->a = limit;
		set_cp_flags(r, limit, coordinate);
		if ((r->f & PORT_FLAG_Z) != 0u)
			r->f = PORT_FLAG_Z | PORT_FLAG_C;
		else
			set_and_flags(r, limit);
	}
	edge = (r->f & PORT_FLAG_Z) != 0u;

	r->b = saved_b;
	r->c = saved_c;
	r->d = (port_u8)(saved_de >> 8);
	r->e = (port_u8)saved_de;
	r->h = (port_u8)(saved_hl >> 8);
	r->l = (port_u8)saved_hl;
	return edge;
}
