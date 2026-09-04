#include "port_state.h"

/* Port of GetDefaultName in engine/movie/oak_speech/oak_speech2.asm.
 * The CopyData tail is the already-proven GetDefaultName.foundName boundary. */

#define NAME_TERMINATOR 0x50u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_H 0x20u
#define PORT_FLAG_N 0x40u
#define PORT_FLAG_Z 0x80u

static void
cp8(struct cpu_register_state *state, port_u8 right)
{
	port_u8 left = state->a;

	state->f = PORT_FLAG_N;
	if (left == right)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		state->f |= PORT_FLAG_H;
	if (left < right)
		state->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_get_default_name(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 requested = state->a;
	port_u8 index = 0;
	port_u16 hl = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u16 start;

	for (;;) {
		start = hl;
		while (memory[hl++] != NAME_TERMINATOR)
			;
		state->a = requested;
		cp8(state, index);
		if (state->f & PORT_FLAG_Z)
			break;
		++index;
	}

	state->b = requested;
	state->c = index;
	state->d = (port_u8)(start >> 8);
	state->e = (port_u8)(start & 0xffu);
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)(hl & 0xffu);
}
