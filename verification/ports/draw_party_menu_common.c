#include "port_state.h"

#define BANK_REDRAW_PARTY_MENU 4u
#define R_ROMB 0xFF00u

/* Port of DrawPartyMenuCommon (home/pokemon.asm): ld b, BANK(RedrawPartyMenu_); jp Bankswitch.
 *
 * Switches the ROM bank to the RedrawPartyMenu_ bank and indirect-jumps (via
 * Bankswitch) to the routine whose address is already in HL. The jp hl target
 * is an explicit boundary; only the bank switch is modeled observably (matching
 * the framework's R_ROMB alias used by port_copy_video_data). */
__attribute__((noinline, used)) void
port_draw_party_menu_common(struct cpu_register_state *state, port_u8 *memory)
{
	state->b = BANK_REDRAW_PARTY_MENU;
	memory[R_ROMB] = state->b; /* ld [rROMB], a ; jp hl is a boundary */
}
