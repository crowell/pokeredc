#include "port_state.h"

#define W_MOVEMENT_FLAGS 0xd736u
#define W_CUR_MAP_TILESET 0xd367u
#define W_TILE_IN_FRONT 0xcfc6u
#define W_TILE_PLAYER_STANDING_ON 0xc45cu
#define W_TILEMAP 0xc3a0u
#define LEDGE_OR_FISHING_BIT 6u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_H 0x20u
#define PORT_FLAG_Z 0x80u

void port_get_tile_and_coords_in_front(struct cpu_register_state *, port_u8 *);
void port_handle_ledges(struct cpu_register_state *, port_u8 *);
void port_check_for_tile_pair_collisions(struct tile_pair_collision_state *,
	const port_u8 *);

static void
and_a(struct cpu_register_state *r)
{
	r->f = r->a == 0u ? PORT_FLAG_Z : 0u;
}

static void
bit_at_hl(struct cpu_register_state *r, port_u8 value)
{
	r->f = (port_u8)(r->f & PORT_FLAG_C) | PORT_FLAG_H;
	if ((value & (port_u8)(1u << LEDGE_OR_FISHING_BIT)) == 0u)
		r->f |= PORT_FLAG_Z;
}

/* Port of CheckForJumpingAndTilePairCollisions in home/overworld.asm. */
__attribute__((noinline, used)) void
port_check_for_jumping_and_tile_pair_collisions(
	struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 saved_hl = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u16 saved_de;
	port_u8 saved_b;
	port_u8 saved_c;
	struct tile_pair_collision_state pairs;

	port_get_tile_and_coords_in_front(r, memory);
	/* BC and DE are pushed after the tile lookup, so the restored values are
	 * the lookup coordinates/tile rather than the caller's original pair. */
	saved_de = (port_u16)(((port_u16)r->d << 8) | r->e);
	saved_b = r->b;
	saved_c = r->c;
	port_handle_ledges(r, memory);

	/* POP BC, POP DE, POP HL restore the caller's collision-table context. */
	r->b = saved_b;
	r->c = saved_c;
	r->d = (port_u8)(saved_de >> 8);
	r->e = (port_u8)saved_de;
	r->h = (port_u8)(saved_hl >> 8);
	r->l = (port_u8)saved_hl;
	and_a(r);
	r->a = memory[W_MOVEMENT_FLAGS];
	bit_at_hl(r, memory[W_MOVEMENT_FLAGS]);
	if ((memory[W_MOVEMENT_FLAGS] & (port_u8)(1u << LEDGE_OR_FISHING_BIT)) != 0u)
		return;

	memory[W_TILE_PLAYER_STANDING_ON] =
		memory[W_TILEMAP + 9u * 20u + 8u];
	pairs.registers = *r;
	pairs.front_tile = memory[W_TILE_IN_FRONT];
	pairs.current_tileset = memory[W_CUR_MAP_TILESET];
	pairs.standing_tile = memory[W_TILE_PLAYER_STANDING_ON];
	port_check_for_tile_pair_collisions(&pairs, memory);
	*r = pairs.registers;
}
