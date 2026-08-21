#include "port_state.h"

struct change_bg_pal_color0_4frames_private_state {
	struct cpu_register_state registers;
};

/* Port of ChangeBGPalColor0_4Frames through GetPredefRegisters boundary. */
__attribute__((noinline, used)) void
port_change_bg_pal_color0_4frames_private(
	struct change_bg_pal_color0_4frames_private_state *state)
{
	(void)state;
}
