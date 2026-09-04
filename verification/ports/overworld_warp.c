#include "port_state.h"

#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_FACING 0xc109u
#define W_TILE_IN_FRONT 0xcfc6u
#define W_CUR_MAP 0xd35eu
#define WARP_TILE_LIST_POINTERS 0x4477u
#define SS_ANNE_BOW 0x63u

void port_get_tile_and_coords_in_front(struct cpu_register_state *,
	port_u8 *);
port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
and_a(struct cpu_register_state *registers)
{
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

static void
scf(struct cpu_register_state *registers)
{
	registers->f = (registers->f & PORT_FLAG_Z) | PORT_FLAG_C;
}

/* Port of IsWarpTileInFrontOfPlayer in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_is_warp_tile_in_front_of_player(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 saved_hl = pair(registers->h, registers->l);
	port_u16 saved_de = pair(registers->d, registers->e);
	port_u8 saved_b = registers->b;
	port_u8 saved_c = registers->c;

	port_get_tile_and_coords_in_front(registers, memory);
	if (memory[W_CUR_MAP] == SS_ANNE_BOW) {
		registers->a = memory[W_TILE_IN_FRONT];
		cp(registers, 0x15);
		if (registers->a == 0x15)
			scf(registers);
		else
			and_a(registers);
		goto done;
	}

	registers->a = memory[W_FACING];
	registers->a >>= 1;
	registers->c = registers->a;
	registers->b = 0;
	{
		port_u16 pointer = (port_u16)(WARP_TILE_LIST_POINTERS +
			registers->c);
		port_u16 list;

		list = memory[pointer++];
		list |= (port_u16)memory[pointer] << 8;
		registers->h = (port_u8)(list >> 8);
		registers->l = (port_u8)list;
	}
	registers->d = 0;
	registers->e = 1;
	{
		struct computed_load_state search;
		port_u8 found;

		search.registers = *registers;
		search.registers.a = memory[W_TILE_IN_FRONT];
		found = port_is_in_array(&search, memory);
		*registers = search.registers;
		(void)found;
	}

done:
	registers->b = saved_b;
	registers->c = saved_c;
	registers->d = (port_u8)(saved_de >> 8);
	registers->e = (port_u8)saved_de;
	registers->h = (port_u8)(saved_hl >> 8);
	registers->l = (port_u8)saved_hl;
}
