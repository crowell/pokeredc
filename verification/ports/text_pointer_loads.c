#include "port_state.h"

/* Ports of the single text-pointer selection routines. Each loads the address
 * of a text resource into HL and returns; no other register or flag is
 * touched. */

static __attribute__((noinline)) void
set_hl(struct cpu_register_state *state, port_u16 value)
{
	state->h = (port_u8)(value >> 8);
	state->l = (port_u8)value;
}

/* PrintPlayerMon1Text (engine/battle/common_text.asm:159) */
__attribute__((noinline, used)) void
port_print_player_mon1_text(struct cpu_register_state *state)
{
	set_hl(state, 0x4ecc); /* PlayerMon1Text */
}

/* PrintComeBackText (engine/battle/common_text.asm:237) */
__attribute__((noinline, used)) void
port_print_come_back_text(struct cpu_register_state *state)
{
	set_hl(state, 0x4f3e); /* ComeBackText */
}

/* LoadPresentsGraphic (engine/movie/intro.asm:359) */
__attribute__((noinline, used)) void
port_load_presents_graphic(struct cpu_register_state *state)
{
	/* Body is a single RET; every register and flag is preserved. */
	(void)state;
}
