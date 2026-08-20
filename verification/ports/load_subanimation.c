#include "port_state.h"

#define W_SUBANIM_COUNTER 0xd087
#define W_SUBANIM_TRANSFORM 0xd08b
#define W_SUBANIM_ADDR_PTR 0xd094
#define W_SUBANIM_SUBENTRY_ADDR 0xd096
#define H_WHOSE_TURN 0xfff3

/* Port of LoadSubanimation's non-enemy, player's-turn path. */
__attribute__((noinline, used)) void
port_load_subanimation_normal(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 pointer = (port_u16)(((port_u16)memory[W_SUBANIM_ADDR_PTR + 1] << 8) |
		memory[W_SUBANIM_ADDR_PTR]);
	port_u16 subanimation = (port_u16)(((port_u16)memory[pointer + 1] << 8) |
		memory[pointer]);
	port_u8 packed = memory[subanimation];
	port_u16 subentry = (port_u16)(subanimation + 1);

	memory[W_SUBANIM_COUNTER] = packed & 0x1f;
	memory[W_SUBANIM_TRANSFORM] = 0;
	memory[W_SUBANIM_SUBENTRY_ADDR] = (port_u8)subentry;
	memory[W_SUBANIM_SUBENTRY_ADDR + 1] = (port_u8)(subentry >> 8);
	state->a = (port_u8)(subentry >> 8);
	state->b = 0;
	state->d = (port_u8)(subentry >> 8);
	state->e = (port_u8)subentry;
	state->h = (port_u8)(subentry >> 8);
	state->l = (port_u8)subentry;
	state->f = 0;
	(void)H_WHOSE_TURN;
}
