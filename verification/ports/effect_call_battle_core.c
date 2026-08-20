#include "port_state.h"

/* Port of EffectCallBattleCore in engine/battle/move_effects/reflect_light_screen.asm.
 *
 * ld b, $0f; jp $35d6. LD B and JP preserve F; the tail jp is the boundary. */

#define EFFECT_CALL_BATTLE_CORE_B 0x0fu

__attribute__((noinline, used)) void
port_effect_call_battle_core(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->b = EFFECT_CALL_BATTLE_CORE_B;
}
