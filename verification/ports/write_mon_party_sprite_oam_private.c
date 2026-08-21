#include "port_state.h"

struct write_mon_party_sprite_oam_private_state {
	struct cpu_register_state registers;
	port_u8 party_index;
};

/* Port of WriteMonPartySpriteOAM through first-frame OAM pointer setup. */
__attribute__((noinline, used)) void
port_write_mon_party_sprite_oam_private(
	struct write_mon_party_sprite_oam_private_state *state)
{
	port_u8 offset = (port_u8)((state->party_index << 4) + 0x10);
	state->registers.h = 0xc3;
	state->registers.l = offset;
	state->registers.b = offset;
	state->registers.c = 0x10;
}
