#include "port_state.h"

/* Port of LoadBattleTransitionTile in engine/battle/battle_transitions.asm. */

#define LBTT_DESTINATION 0x8ff0u
#define LBTT_SOURCE      0x4a59u
#define LBTT_BANK_COUNT  0x1c01u

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

__attribute__((noinline, used)) void
port_load_battle_transition_tile(struct cpu_register_state *state, port_u8 *memory)
{
	state->h = (port_u8)(LBTT_DESTINATION >> 8);
	state->l = (port_u8)LBTT_DESTINATION;
	state->d = (port_u8)(LBTT_SOURCE >> 8);
	state->e = (port_u8)LBTT_SOURCE;
	state->b = (port_u8)(LBTT_BANK_COUNT >> 8);
	state->c = (port_u8)LBTT_BANK_COUNT;
	port_copy_video_data(state, memory);
}
