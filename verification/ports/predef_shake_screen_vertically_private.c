#include "port_state.h"

struct predef_shake_vertical_private_state {
	struct cpu_register_state registers;
	port_u8 disable_vblank_wy_update;
};

/* Port of PredefShakeScreenVertically through animation setup. */
__attribute__((noinline, used)) void
port_predef_shake_screen_vertically_private(
	struct predef_shake_vertical_private_state *state)
{
	state->registers.a = 1;
	state->disable_vblank_wy_update = 1;
}
