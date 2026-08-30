#include "port_state.h"

struct print_send_out_state {
	struct cpu_register_state registers;
	port_u8 current_hp_low;
	port_u8 current_hp_high;
};

#define W_TEXT_BOX_ID 0xd125u

void port_print_text(struct cpu_register_state *, port_u8 *);

/* Port of the PrintSendOutMonMessage entry through the GoText branch. */
__attribute__((noinline, used)) void
port_print_send_out_mon_message(struct print_send_out_state *state,
	port_u8 *memory)
{
	port_u8 value = state->current_hp_low | state->current_hp_high;

	state->registers.a = value;
	state->registers.f = value == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0x4e;
	state->registers.l = 0xae;
	if (value == 0) {
		port_print_text(&state->registers, memory);
	}
}
