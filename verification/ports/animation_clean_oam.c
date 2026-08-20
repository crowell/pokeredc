#include "port_state.h"

#define OAM_START 0xfe00
#define OAM_SIZE 160

/* Port of AnimationCleanOAM; DelayFrame is timing-only and ClearSprites clears OAM. */
__attribute__((noinline, used)) void
port_animation_clean_oam(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 offset;

	for (offset = 0; offset < OAM_SIZE; offset++)
		memory[(port_u16)(OAM_START + offset)] = 0;
	(void)state;
}
