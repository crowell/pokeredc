#include "port_state.h"

struct write_party_oam_index_private_state {
	struct cpu_register_state registers;
	port_u8 party_index;
};

/* Port of WriteMonPartySpriteOAMByPartyIndex through species-pointer setup. */
__attribute__((noinline, used)) void
port_write_mon_party_sprite_oam_by_party_index_private(
	struct write_party_oam_index_private_state *state)
{
	state->registers.a = state->party_index;
	state->registers.h = 0xd1;
	state->registers.l = 0x64;
	state->registers.d = 0;
	state->registers.e = state->party_index;
}
