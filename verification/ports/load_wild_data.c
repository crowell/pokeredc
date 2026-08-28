#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_GRASS_RATE 0xd887u
#define W_GRASS_MONS 0xd888u
#define W_WATER_RATE 0xd8a4u
#define W_WATER_MONS 0xd8a5u
#define WILD_DATA_POINTERS 0x4eebu
#define WILD_DATA_LENGTH 21u

void port_copy_data(struct cpu_register_state *, port_u8 *);

static port_u16 pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void set_pair(struct cpu_register_state *registers, char which,
	port_u16 value)
{
	if (which == 'h') {
		registers->h = (port_u8)(value >> 8);
		registers->l = (port_u8)value;
	} else if (which == 'd') {
		registers->d = (port_u8)(value >> 8);
		registers->e = (port_u8)value;
	} else {
		registers->b = (port_u8)(value >> 8);
		registers->c = (port_u8)value;
	}
}

static void add_hl_bc(struct cpu_register_state *registers)
{
	port_u16 hl = pair(registers->h, registers->l);
	port_u16 bc = pair(registers->b, registers->c);
	port_u16 result = (port_u16)(hl + bc);
	port_u8 flags = registers->f & PORT_FLAG_Z;
	if ((hl & 0x0fffu) + (bc & 0x0fffu) > 0x0fffu)
		flags |= PORT_FLAG_H;
	if ((unsigned long)hl + bc > 0xfffful)
		flags |= PORT_FLAG_C;
	registers->f = flags;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Port of LoadWildData in engine/overworld/wild_mons.asm. */
__attribute__((noinline, used)) void
port_load_wild_data(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 map = memory[W_CUR_MAP];
	port_u16 pointer_address = (port_u16)(WILD_DATA_POINTERS + (port_u16)map * 2u);
	port_u16 source = (port_u16)(memory[pointer_address] |
		((port_u16)memory[(port_u16)(pointer_address + 1u)] << 8));
	port_u8 grass_rate;
	port_u8 water_rate;
	struct cpu_register_state copy;

	registers->b = 0;
	registers->c = map;
	registers->h = (port_u8)(pointer_address >> 8);
	registers->l = (port_u8)pointer_address;
	registers->a = memory[pointer_address];
	registers->h = memory[(port_u16)(pointer_address + 1u)];
	registers->l = registers->a;
	source = pair(registers->h, registers->l);
	registers->a = memory[source++];
	registers->h = (port_u8)(source >> 8);
	registers->l = (port_u8)source;
	grass_rate = registers->a;
	memory[W_GRASS_RATE] = grass_rate;
	registers->f = grass_rate == 0u ? PORT_FLAG_Z : 0;
	if (grass_rate != 0u) {
		copy = *registers;
		copy.h = registers->h;
		copy.l = registers->l;
		set_pair(&copy, 'd', W_GRASS_MONS);
		set_pair(&copy, 'b', (port_u16)(WILD_DATA_LENGTH - 1u));
		port_copy_data(&copy, memory);
		*registers = copy;
		registers->h = (port_u8)(source >> 8);
		registers->l = (port_u8)source;
		set_pair(registers, 'b', (port_u16)(WILD_DATA_LENGTH - 1u));
		add_hl_bc(registers);
	}
	{
		port_u16 water_source = pair(registers->h, registers->l);
		registers->a = memory[water_source];
		water_source = (port_u16)(water_source + 1u);
		registers->h = (port_u8)(water_source >> 8);
		registers->l = (port_u8)water_source;
	}
	water_rate = registers->a;
	memory[W_WATER_RATE] = water_rate;
	registers->f = water_rate == 0u ? PORT_FLAG_Z : 0;
	if (water_rate == 0u)
		return;
	set_pair(registers, 'd', W_WATER_MONS);
	set_pair(registers, 'b', (port_u16)(WILD_DATA_LENGTH - 1u));
	port_copy_data(registers, memory);
}
