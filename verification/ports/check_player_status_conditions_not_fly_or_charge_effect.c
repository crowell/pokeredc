#include "port_state.h"

/* Port of CheckPlayerStatusConditions.NotFlyOrChargeEffect in engine/battle/core.asm.
 *
 * ld hl, $580a; jp $5a37. LD HL and JP preserve F; the local return JP is the boundary. */

#define CHECK_PLAYER_STATUS_CONDITIONS_NOT_FLY_OR_CHARGE_EFFECT_HL 0x580au

__attribute__((noinline, used)) void
port_check_player_status_conditions_not_fly_or_charge_effect(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(CHECK_PLAYER_STATUS_CONDITIONS_NOT_FLY_OR_CHARGE_EFFECT_HL >> 8);
    state->l = (port_u8)(CHECK_PLAYER_STATUS_CONDITIONS_NOT_FLY_OR_CHARGE_EFFECT_HL & 0xff);
}
