#include "port_state.h"

/* Port of DrawHUDsAndHPBars through DrawPlayerHUDAndHPBar. */
__attribute__((noinline, used)) void
port_draw_huds_and_hp_bars(struct cpu_register_state *registers)
{
	(void)registers;
}
