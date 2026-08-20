#include "port_state.h"

#define W_TEMP_PIC 0xc6e8u
#define PIC_SIZE_BYTES 0x0310u

/* FillMemory is the explicit continuation boundary for this entry prefix. */
__attribute__((noinline, used)) void
port_animation_substitute(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;
	state->h = (port_u8)(W_TEMP_PIC >> 8);
	state->l = (port_u8)W_TEMP_PIC;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	state->b = (port_u8)(PIC_SIZE_BYTES >> 8);
	state->c = (port_u8)PIC_SIZE_BYTES;
}
