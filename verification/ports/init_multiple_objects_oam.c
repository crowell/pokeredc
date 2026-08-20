#include "port_state.h"

#define W_WHICH_BATTLE_ANIM_TILESET 0xd09fu

/* LoadMoveAnimationTiles is the explicit continuation boundary. */
__attribute__((noinline, used)) void
port_init_multiple_objects_oam(struct cpu_register_state *state,
    port_u8 *memory)
{
	memory[W_WHICH_BATTLE_ANIM_TILESET] = state->a;
}
