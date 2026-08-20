#include "port_state.h"

/* Port of ViridianGymPlayerSpinningScript.ViridianGymLoadSpinnerArrow in
 * scripts/ViridianGym.asm.
 *
 * farjp LoadSpinnerArrowTiles: ld b, $11; ld hl, $4fd7; jp $35d6.
 * The setup instructions preserve F; the local bankswitch JP is the boundary. */

#define VIRIDIAN_GYM_PLAYER_SPINNING_SCRIPT_LOAD_SPINNER_ARROW_HL 0x4fd7u
#define VIRIDIAN_GYM_PLAYER_SPINNING_SCRIPT_LOAD_SPINNER_ARROW_B 0x11u

__attribute__((noinline, used)) void
port_viridian_gym_player_spinning_script_load_spinner_arrow(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(VIRIDIAN_GYM_PLAYER_SPINNING_SCRIPT_LOAD_SPINNER_ARROW_HL >> 8);
    state->l = (port_u8)(VIRIDIAN_GYM_PLAYER_SPINNING_SCRIPT_LOAD_SPINNER_ARROW_HL & 0xff);
    state->b = VIRIDIAN_GYM_PLAYER_SPINNING_SCRIPT_LOAD_SPINNER_ARROW_B;
}
