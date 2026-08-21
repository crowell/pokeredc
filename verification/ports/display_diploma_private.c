#include "port_state.h"

struct display_diploma_private_state {
	struct cpu_register_state registers;
	port_u8 update_sprites;
	port_u8 status_flags5;
};

/* Port of DisplayDiploma through initial display/status setup. */
__attribute__((noinline, used)) void
port_display_diploma_private(struct display_diploma_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = 0;
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->update_sprites = 0;
	state->status_flags5 |= 0x40;
}
