#include "port_state.h"

/* Port of TitleScreenCopyTileMapToVRAM in engine/movie/title.asm.
 *
 * The routine is:
 *
 *   ldh [hAutoBGTransferDest + 1], a
 *   jp Delay3
 *
 * It stores the incoming accumulator (the high byte of the destination
 * pointer, supplied by the caller) and then executes the Delay3 tail.
 */

#define H_AUTO_BG_TRANSFER_DEST_HI 0xffbd

void port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_title_screen_copy_tilemap_to_vram(struct cpu_register_state *state,
	port_u8 *memory)
{
	/* ldh [hAutoBGTransferDest + 1], a */
	memory[H_AUTO_BG_TRANSFER_DEST_HI] = state->a;
	port_delay3(state, memory);
}
