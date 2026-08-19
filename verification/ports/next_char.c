#include "port_state.h"

/* Port of NextChar in home/text.asm.
 *
 * The routine is:
 *
 *   inc de
 *   jp PlaceNextChar
 *
 * It advances the text-pointer in DE by one byte and transfers to
 * PlaceNextChar, which is an explicit boundary. `inc de` does not modify
 * any flags on the SM83, so the only observable effect is DE = DE + 1.
 */

__attribute__((noinline, used)) void
port_next_char(struct cpu_register_state *state)
{
	/* inc de */
	port_u16 de = ((port_u16)state->d << 8) | state->e;
	de = (de + 1) & 0xFFFF;
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;
}
