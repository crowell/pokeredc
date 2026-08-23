#include "port_state.h"

/* Port of CreditsCopyTileMapToVRAM in engine/movie/credits.asm.
 *
 * Sets the auto-BG-transfer destination to the caller-supplied HL pointer and
 * enables the auto BG transfer, then executes the Delay3 tail. The body is:
 *
 *   ld a, l
 *   ldh [hAutoBGTransferDest], a
 *   ld a, h
 *   ldh [hAutoBGTransferDest + 1], a
 *   ld a, 1
 *   ldh [hAutoBGTransferEnabled], a
 *   jp Delay3
 *
 * H and L remain intact while Delay3 supplies the final A/F/C state.
 */

#define H_AUTO_BG_TRANSFER_DEST 0xffbcu
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau

void port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_credits_copy_tilemap_to_vram(struct cpu_register_state *state,
	port_u8 *memory)
{
	/* ld a, l ; ldh [hAutoBGTransferDest], a */
	memory[H_AUTO_BG_TRANSFER_DEST] = state->l;

	/* ld a, h ; ldh [hAutoBGTransferDest + 1], a */
	memory[H_AUTO_BG_TRANSFER_DEST + 1] = state->h;

	/* ld a, 1 ; ldh [hAutoBGTransferEnabled], a
	 * SM83 ``ld a, r`` clears Z/N/H/C, so the final flags are all zero. */
	state->a = 1;
	state->f = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	port_delay3(state, memory);
}
