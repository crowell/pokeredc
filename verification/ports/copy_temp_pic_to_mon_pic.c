#include "port_state.h"

#define H_WHOSE_TURN 0xfff3u
#define V_FRONT_PIC  0x9000u
#define V_BACK_PIC   0x9310u
#define W_TEMP_PIC   0xc6e8u
#define PIC_SIZE     0x31u

/* CopyVideoData is the explicit continuation for this setup. */
__attribute__((noinline, used)) void
port_copy_temp_pic_to_mon_pic(struct cpu_register_state *state,
    port_u8 *memory)
{
	port_u8 whose_turn = memory[H_WHOSE_TURN];
	port_u16 source = whose_turn == 0 ? V_BACK_PIC : V_FRONT_PIC;

	state->h = (port_u8)(source >> 8);
	state->l = (port_u8)source;
	state->d = (port_u8)(W_TEMP_PIC >> 8);
	state->e = (port_u8)W_TEMP_PIC;
	state->b = (port_u8)(PIC_SIZE >> 8);
	state->c = (port_u8)PIC_SIZE;
	state->a = whose_turn;
	state->f = (port_u8)(PORT_FLAG_H |
	    (whose_turn == 0 ? PORT_FLAG_Z : 0));
}
