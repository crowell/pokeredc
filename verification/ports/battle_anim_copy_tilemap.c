#include "port_state.h"

/* Port of BattleAnimCopyTileMapToVRAM in engine/battle/animations.asm.
 *
 * The routine is:
 *
 *   ld a, h
 *   ldh [hAutoBGTransferDest + 1], a
 *   ld a, l
 *   ldh [hAutoBGTransferDest], a
 *   jp Delay3
 *
 * It stores the caller's HL pointer into the auto-BG-transfer destination
 * (low byte L at hAutoBGTransferDest, high byte H at hAutoBGTransferDest+1)
 * and then executes Delay3. H and L remain intact while the delay supplies
 * the terminal A/F/C state.
 */

#define H_AUTO_BG_TRANSFER_DEST 0xffbcu
#define H_AUTO_BG_TRANSFER_DEST_HI 0xffbd

void port_delay3(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_battle_anim_copy_tilemap_to_vram(struct cpu_register_state *state,
	port_u8 *memory)
{
	/* ld a, h ; ldh [hAutoBGTransferDest + 1], a */
	memory[H_AUTO_BG_TRANSFER_DEST_HI] = state->h;

	/* ld a, l ; ldh [hAutoBGTransferDest], a */
	state->a = state->l;
	state->f = 0;
	memory[H_AUTO_BG_TRANSFER_DEST] = state->l;
	port_delay3(state, memory);
}
