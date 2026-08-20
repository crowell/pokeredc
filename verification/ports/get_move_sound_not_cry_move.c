#include "port_state.h"

struct get_move_sound_not_cry_state {
    struct cpu_register_state registers;
    port_u8 source0;
    port_u8 source1;
    port_u8 frequency;
    port_u8 tempo;
};

/* Port of GetMoveSound.NotCryMove in engine/battle/animations.asm.
 *
 * ld a, [hli]; ld [wFrequencyModifier], a; ld a, [hli];
 * ld [wTempoModifier], a; ld a, b; ret.
 * The explicit state records both memory reads and writes; RET is the boundary. */

__attribute__((noinline, used)) void
port_get_move_sound_not_cry_move(struct get_move_sound_not_cry_state *state)
{
    state->frequency = state->source0;
    state->tempo = state->source1;
    port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
    hl += 2;
    state->registers.h = (port_u8)(hl >> 8);
    state->registers.l = (port_u8)hl;
    state->registers.a = state->registers.b;
}
