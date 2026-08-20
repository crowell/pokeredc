#include "port_state.h"

struct play_battle_animation_got_id_state {
    struct cpu_register_state registers;
    port_u8 move_animation_a;
    port_u8 move_animation_f;
};

/* Port of PlayBattleAnimationGotID in engine/battle/effects.asm.
 *
 * PUSH HL/DE/BC; LD A,8; CALL MoveAnimation; POP BC/DE/HL; RET.
 * MoveAnimation's returned A/F are explicit compositional state inputs; the
 * balanced stack sequence preserves BC/DE/HL and the PC-portable contract. */

__attribute__((noinline, used)) void
port_play_battle_animation_got_id(struct play_battle_animation_got_id_state *state)
{
    state->registers.a = state->move_animation_a;
    state->registers.f = state->move_animation_f;
}
