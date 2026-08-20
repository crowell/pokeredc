#include "port_state.h"

#define W_SLIDE_MON_DELAY 0xd08b
#define H_WHOSE_TURN 0xfff3
#define W_TILE_MAP 0xc3a0u
#define SCREEN_WIDTH 20u

/*
 * _AnimationSlideMonOff's first continuation is the per-tile helper call.
 * Model the complete setup and stop immediately before PlayerNextTile or
 * EnemyNextTile, leaving the helper itself as an explicit boundary.
 */
__attribute__((noinline, used)) void
port_animation_slide_mon_off_private(struct cpu_register_state *state,
    port_u8 *memory)
{
	port_u8 whose_turn = memory[H_WHOSE_TURN];
	port_u16 hl;

	if (whose_turn != 0)
		hl = (port_u16)(W_TILE_MAP + 12u);
	else
		hl = (port_u16)(W_TILE_MAP + 5u * SCREEN_WIDTH);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
	state->d = 8;
	state->b = 7;
	state->c = 8;
	state->a = whose_turn;
	state->f = (port_u8)(PORT_FLAG_H |
	    (whose_turn == 0 ? PORT_FLAG_Z : 0));
}
