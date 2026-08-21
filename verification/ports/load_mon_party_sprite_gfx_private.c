#include "port_state.h"

struct load_mon_party_sprite_gfx_private_state {
	struct cpu_register_state registers;
};

/* Port of LoadMonPartySpriteGfx through LoadAnimSpriteGfx setup. */
__attribute__((noinline, used)) void
port_load_mon_party_sprite_gfx_private(
	struct load_mon_party_sprite_gfx_private_state *state)
{
	state->registers.h = 0x57;
	state->registers.l = 0xc0;
	state->registers.a = 0x1c;
	state->registers.b = 0;
	state->registers.c = 0;
}
