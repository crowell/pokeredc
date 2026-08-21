#include "port_state.h"

struct load_anim_sprite_gfx_private_state {
	struct cpu_register_state registers;
};

/* Port of LoadAnimSpriteGfx through zeroed CopyVideoData offset setup. */
__attribute__((noinline, used)) void
port_load_anim_sprite_gfx_private(struct load_anim_sprite_gfx_private_state *state)
{
	state->registers.b = 0;
	state->registers.c = 0;
}
