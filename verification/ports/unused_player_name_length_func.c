#include "port_state.h"

/* Port of UnusedPlayerNameLengthFunc in engine/events/diploma.asm.
 *
 * Leftover JPN helper: walk the player-name buffer from wPlayerName, count
 * non-terminator bytes, and leave BC = -(name length) with B = $ff and
 * C = 0 - length (mod 256). Terminates at the '@' ($50) text marker. */
#define UNLEN_W_PLAYER_NAME 0xd158u
#define UNLEN_TERMINATOR 0x50u
#define UNLEN_NAME_LENGTH 11u

__attribute__((noinline, used)) void
port_unused_player_name_length_func(
	struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = UNLEN_W_PLAYER_NAME;
	port_u8 i;
	state->b = 0xffu;
	state->c = 0x00u;
	for (i = 0; i < UNLEN_NAME_LENGTH + 1u; i++) {
		state->a = memory[hl];
		hl = (port_u16)(hl + 1u);
		if (state->a == UNLEN_TERMINATOR) {
			state->f = (port_u8)(PORT_FLAG_N | PORT_FLAG_Z);
			state->h = (port_u8)(hl >> 8);
			state->l = (port_u8)(hl & 0xffu);
			return;
		}
		state->c = (port_u8)(state->c - 1u);
	}
}
