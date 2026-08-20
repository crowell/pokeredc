#include "port_state.h"

struct trade_anim_common_state {
    struct cpu_register_state registers;
    port_u8 options;
    port_u8 scy;
    port_u8 scx;
    port_u8 loop_b;
    port_u8 loop_c;
    port_u8 loop_d;
    port_u8 loop_e;
    port_u8 loop_h;
    port_u8 loop_l;
};

/* Port of TradeAnimCommon in engine/movie/trade.asm.
 *
 * The setup zeroes options/SCY/SCX, dispatches the trade-function loop, and
 * restores the three saved bytes. The loop's returned register set is an
 * explicit compositional input; the final POP AF restores the original F and
 * options byte. No raw Game Boy memory addresses remain in the contract. */

__attribute__((noinline, used)) void
port_trade_anim_common(struct trade_anim_common_state *state)
{
    port_u8 original_f = state->registers.f;
    state->registers.b = state->loop_b;
    state->registers.c = state->loop_c;
    state->registers.d = state->loop_d;
    state->registers.e = state->loop_e;
    state->registers.h = state->loop_h;
    state->registers.l = state->loop_l;
    state->registers.a = state->options;
    state->registers.f = original_f;
}
