#include "port_state.h"

/* Port of Route23PrintOhThatsTheBadgeTextScript in scripts/Route23.asm:
 *
 *   ld hl, Route23OhThatIsTheBadgeText
 *   jp PrintText
 */

void port_print_text(struct cpu_register_state *, port_u8 *);

#define ROUTE23_OH_THAT_IS_THE_BADGE_TEXT_HL 0x539eu

__attribute__((noinline, used)) void
port_route23_print_oh_thats_the_badge_text_script(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(ROUTE23_OH_THAT_IS_THE_BADGE_TEXT_HL >> 8);
	state->l = (port_u8)(ROUTE23_OH_THAT_IS_THE_BADGE_TEXT_HL & 0xff);
	port_print_text(state, memory);
}
