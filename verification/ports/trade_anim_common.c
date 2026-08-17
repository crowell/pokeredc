#include "port_state.h"

#define W_OPTIONS 0xd355u
#define H_SCY 0xffafu
#define H_SCX 0xffaeu

/* Port of TradeAnimCommon (engine/movie/trade.asm).
 *
 * Saves wOptions/hSCY/hSCX, zeroes them for the duration of the trade-animation
 * sequence, then restores them at the end. The per-function animation steps in
 * the sequence (jp hl per entry) are explicit boundaries, so the save/zero/
 * restore of the three globals is modeled; the net effect is that they are
 * unchanged (the zeroed window is the documented boundary region). */
__attribute__((noinline, used)) void
port_trade_anim_common(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 saved_options = memory[W_OPTIONS];
	port_u8 saved_scy = memory[H_SCY];
	port_u8 saved_scx = memory[H_SCX];
	memory[W_OPTIONS] = 0;
	memory[H_SCY] = 0;
	memory[H_SCX] = 0;
	/* run the trade-function sequence (jp hl per entry) -- boundary */
	memory[H_SCX] = saved_scx;
	memory[H_SCY] = saved_scy;
	memory[W_OPTIONS] = saved_options;
}
