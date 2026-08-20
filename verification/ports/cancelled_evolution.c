#include "port_state.h"

struct cancelled_evolution_state {
    struct cpu_register_state registers;
    port_u8 reload_a;
    port_u8 reload_f;
    port_u8 reload_b;
    port_u8 reload_c;
    port_u8 reload_d;
    port_u8 reload_e;
    port_u8 reload_h;
    port_u8 reload_l;
    port_u8 saved_h;
    port_u8 saved_l;
};

/* Port of CancelledEvolution in engine/pokemon/evos_moves.asm.
 *
 * The text, clear-screen, and tileset-reload calls are explicit compositional
 * callee boundaries. The final party-loop JP is a control-flow boundary; the
 * reload callee's complete register result is the observable output. */

__attribute__((noinline, used)) void
port_cancelled_evolution(struct cancelled_evolution_state *state)
{
    state->registers.a = state->reload_a;
    state->registers.f = state->reload_f;
    state->registers.b = state->reload_b;
    state->registers.c = state->reload_c;
    state->registers.d = state->reload_d;
    state->registers.e = state->reload_e;
    state->registers.h = state->reload_h;
    state->registers.l = state->reload_l;
}
