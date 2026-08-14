#include "port_state.h"

/* Port of AnimCutGrass_SwapOAMEntries in engine/overworld/cut2.asm.
 *
 * The routine swaps the two OAM entries at wShadowOAMSprite36 and
 * wShadowOAMSprite38 using wBuffer as scratch: it copies 2*OBJ_SIZE (8) bytes
 * from wShadowOAMSprite36 into wBuffer, then from wShadowOAMSprite38 into
 * wShadowOAMSprite36, then from wBuffer into wShadowOAMSprite38. Each byte-wise
 * copy is delegated to the proven CopyData loop. */
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

#define SWAP_LEN 8
#define ADDR_SPRITE36 0xc390
#define ADDR_BUFFER 0xcee9
#define ADDR_SPRITE38 0xc398

__attribute__((noinline, used)) void
port_anim_cut_grass_swap_oam_entries(struct cpu_register_state *state,
	port_u8 *memory)
{
	state->h = (port_u8)(ADDR_SPRITE36 >> 8);
	state->l = (port_u8)ADDR_SPRITE36;
	state->d = (port_u8)(ADDR_BUFFER >> 8);
	state->e = (port_u8)ADDR_BUFFER;
	state->b = 0;
	state->c = SWAP_LEN;
	port_copy_data(state, memory);

	state->h = (port_u8)(ADDR_SPRITE38 >> 8);
	state->l = (port_u8)ADDR_SPRITE38;
	state->d = (port_u8)(ADDR_SPRITE36 >> 8);
	state->e = (port_u8)ADDR_SPRITE36;
	state->b = 0;
	state->c = SWAP_LEN;
	port_copy_data(state, memory);

	state->h = (port_u8)(ADDR_BUFFER >> 8);
	state->l = (port_u8)ADDR_BUFFER;
	state->d = (port_u8)(ADDR_SPRITE38 >> 8);
	state->e = (port_u8)ADDR_SPRITE38;
	state->b = 0;
	state->c = SWAP_LEN;
	port_copy_data(state, memory);
}
