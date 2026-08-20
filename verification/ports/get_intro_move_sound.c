#include "port_state.h"

struct get_intro_move_sound_state {
    struct cpu_register_state registers;
    port_u8 get_move_sound_a;
    port_u8 get_move_sound_f;
};

/* Port of GetIntroMoveSound in engine/battle/animations.asm.
 *
 * ld a,b; call GetMoveSound; ld b,a; ret.
 * The callee's returned A/F are explicit state inputs, making this a sound
 * compositional wrapper proof and keeping the contract PC-portable. */

__attribute__((noinline, used)) void
port_get_intro_move_sound(struct get_intro_move_sound_state *state)
{
    state->registers.a = state->registers.b;
    state->registers.a = state->get_move_sound_a;
    state->registers.f = state->get_move_sound_f;
    state->registers.b = state->registers.a;
}
