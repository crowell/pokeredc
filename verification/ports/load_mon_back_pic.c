#include "port_state.h"

struct load_mon_back_pic_state {
	struct cpu_register_state registers;
	port_u8 battle_mon_species;
};

/* Port of LoadMonBackPic through ClearScreenArea. */
__attribute__((noinline, used)) void
port_load_mon_back_pic(struct load_mon_back_pic_state *state)
{
	state->registers.a = state->battle_mon_species;
	state->registers.h = 0xc4;
	state->registers.l = 0x05;
	state->registers.b = 7;
	state->registers.c = 8;
}
