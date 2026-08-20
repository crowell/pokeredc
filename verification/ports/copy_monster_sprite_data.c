#include "port_state.h"

#define TILE_SIZE 0x10u
#define MONSTER_SPRITE_BANK 5u

/* FarCopyData2 is the explicit continuation boundary for this helper. */
__attribute__((noinline, used)) void
port_copy_monster_sprite_data(struct cpu_register_state *state,
    port_u8 *memory)
{
	(void)memory;
	state->b = (port_u8)(TILE_SIZE >> 8);
	state->c = (port_u8)TILE_SIZE;
	state->a = (port_u8)MONSTER_SPRITE_BANK;
}
