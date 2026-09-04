#include "port_state.h"

#define W_JOY_IGNORE 0x416bu
#define H_LOADED_ROM_BANK 0xffb8u

void port_load_map_data(struct reload_map_data_state *, port_u8 *);

/* Port of EnterMap through the LoadMapData call boundary. Later map-entry
 * flag handling, warp animation, and sprite updates remain outside this
 * proof domain. */
__attribute__((noinline, used)) void
port_enter_map(struct cpu_register_state *state, port_u8 *memory)
{
	struct reload_map_data_state map = {0};

	state->a = 0xff;
	memory[W_JOY_IGNORE] = state->a;
	map.registers = *state;
	port_load_map_data(&map, memory);
	*state = map.registers;
}
