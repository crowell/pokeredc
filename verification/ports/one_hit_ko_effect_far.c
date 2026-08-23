#include "port_state.h"

/* Port of OneHitKOEffect in engine/battle/effects.asm:
 *
 *   ld hl, OneHitKOEffect_   ; $7f57 in bank $0c
 *   ld b, BANK(OneHitKOEffect_)
 *   jp Bankswitch            ; $35d6
 *
 * jpfar thunk: the Bankswitch dispatcher is the path boundary and the
 * far-target hand-off state (B = target bank, HL = target address) is the
 * observable.
 */

#define ONE_HIT_KO_EFFECT_HL 0x7f57u
#define ONE_HIT_KO_EFFECT_BANK 0x0cu

__attribute__((noinline, used)) void
port_one_hit_ko_effect_far(struct cpu_register_state *state)
{
	state->h = (port_u8)(ONE_HIT_KO_EFFECT_HL >> 8);
	state->l = (port_u8)(ONE_HIT_KO_EFFECT_HL & 0xff);
	state->b = ONE_HIT_KO_EFFECT_BANK;
}
