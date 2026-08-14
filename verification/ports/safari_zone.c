#include "port_state.h"

/* Port of SafariZoneGameStillGoing in
 * engine/events/hidden_events/safari_game.asm. It clears wSafariZoneGameOver
 * (via XOR A followed by the absolute store) and returns. */
__attribute__((noinline, used)) void
port_safari_zone_game_still_going(struct safari_zone_game_still_going_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z; /* XOR A sets Z, clears N/H/C */
	state->safari_zone_game_over = 0;
}
