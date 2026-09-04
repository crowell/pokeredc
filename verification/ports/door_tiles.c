#include "port_state.h"

#define DOOR_TILE_ID_POINTERS 0x662cu
#define W_CUR_MAP_TILESET 0xd367u
#define STANDING_TILE 0xc45cu

port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
compare(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	registers->f = PORT_FLAG_N;
	if (left == right)
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

/* Port of IsPlayerStandingOnDoorTile in engine/overworld/doors.asm. */
__attribute__((noinline, used)) void
port_is_player_standing_on_door_tile(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 saved_de = pair(registers->d, registers->e);
	struct computed_load_state search;
	port_u8 found;

	/* call IsInArray with the same table, stride, and current tileset. */
	search.registers = *registers;
	search.registers.a = memory[W_CUR_MAP_TILESET];
	search.registers.h = (port_u8)(DOOR_TILE_ID_POINTERS >> 8);
	search.registers.l = (port_u8)DOOR_TILE_ID_POINTERS;
	search.registers.d = 0;
	search.registers.e = 3;
	found = port_is_in_array(&search, memory);
	registers->a = search.registers.a;
	registers->f = search.registers.f;
	registers->b = search.registers.b;
	registers->c = search.registers.c;
	registers->h = search.registers.h;
	registers->l = search.registers.l;
	registers->d = (port_u8)(saved_de >> 8);
	registers->e = (port_u8)saved_de;
	if (found != 1u) {
		and_a(registers);
		return;
	}

	{
		port_u16 pointer = pair(registers->h, registers->l);
		port_u16 list;

		pointer++;
		list = memory[pointer++];
		list |= (port_u16)memory[pointer] << 8;
		registers->h = (port_u8)(list >> 8);
		registers->l = (port_u8)list;

		/* The lda_coord 8, 9 instruction reads row 9, column 8. */
		port_u8 standing = memory[STANDING_TILE];
		registers->b = standing;
		for (;;) {
			port_u16 current = pair(registers->h, registers->l);
			registers->a = memory[current++];
			registers->h = (port_u8)(current >> 8);
			registers->l = (port_u8)current;
			and_a(registers);
			if ((registers->f & PORT_FLAG_Z) != 0)
				break;
			compare(registers, standing);
			if (registers->a == standing) {
				/* SCF preserves Z and clears N/H while setting C. */
				registers->f = (registers->f & PORT_FLAG_Z) | PORT_FLAG_C;
				break;
			}
		}
	}
}
