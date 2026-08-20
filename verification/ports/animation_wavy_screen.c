#include "port_state.h"

#define V_BG_MAP0 0x9800u

/* BattleAnimCopyTileMapToVRAM is the explicit continuation boundary. */
__attribute__((noinline, used)) void
port_animation_wavy_screen(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;
	state->h = (port_u8)(V_BG_MAP0 >> 8);
	state->l = (port_u8)V_BG_MAP0;
}
