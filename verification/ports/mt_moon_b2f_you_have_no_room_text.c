#include "port_state.h"

/* Port of MtMoonB2FYouHaveNoRoomText in scripts/MtMoonB2F.asm:
 *
 *   ld hl, .Text
 *   call PrintText
 *   jp TextScriptEnd
 */

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_text_script_end(struct cpu_register_state *);

#define MT_MOON_B2F_YOU_HAVE_NO_ROOM_TEXT_HL 0x5f7fu

__attribute__((noinline, used)) void
port_mt_moon_b2f_you_have_no_room_text(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(MT_MOON_B2F_YOU_HAVE_NO_ROOM_TEXT_HL >> 8);
	state->l = (port_u8)(MT_MOON_B2F_YOU_HAVE_NO_ROOM_TEXT_HL & 0xff);
	port_print_text(state, memory);
	port_text_script_end(state);
}
