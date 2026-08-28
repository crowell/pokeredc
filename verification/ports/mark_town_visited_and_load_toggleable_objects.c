#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_TOWN_VISITED 0xd70bu
#define W_TOGGLE_LIST 0xd5ceu
#define TOGGLE_POINTERS 0x48f5u
#define TOGGLE_STATES 0x4aeau
#define FIRST_ROUTE_MAP 0x0cu

static port_u16 read_word(const port_u8 *memory, port_u16 address)
{
	return (port_u16)(memory[address] | ((port_u16)memory[(port_u16)(address + 1u)] << 8));
}

static port_u8 cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;
	if ((left & 0x0fu) < (right & 0x0fu)) flags |= PORT_FLAG_H;
	if (left < right) flags |= PORT_FLAG_C;
	if (result == 0u) flags |= PORT_FLAG_Z;
	return flags;
}

__attribute__((noinline, used)) void
port_mark_town_visited_and_load_toggleable_objects(
	struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 map = memory[W_CUR_MAP];
	if (map < FIRST_ROUTE_MAP)
		memory[W_TOWN_VISITED + (map >> 3)] |= (port_u8)(1u << (map & 7u));
	port_u16 source = read_word(memory, (port_u16)(TOGGLE_POINTERS + (port_u16)map * 2u));
	port_u16 offset = source >= TOGGLE_STATES ? (port_u16)((source - TOGGLE_STATES) / 3u) : 0u;
	port_u16 destination = W_TOGGLE_LIST;
	for (;;) {
		port_u8 record_map = memory[source++];
		if (record_map == 0xffu) {
			registers->f = PORT_FLAG_Z | PORT_FLAG_N;
			break;
		}
		if (record_map != map) {
			registers->f = cp_flags(record_map, map);
			break;
		}
		memory[destination++] = memory[source++];
		memory[destination++] = (port_u8)offset++;
		registers->c++;
		source++;
	}
	memory[destination] = 0xffu;
	registers->a = 0xffu;
	registers->h = (port_u8)(source >> 8); registers->l = (port_u8)source;
	registers->d = (port_u8)(destination >> 8); registers->e = (port_u8)destination;
}
