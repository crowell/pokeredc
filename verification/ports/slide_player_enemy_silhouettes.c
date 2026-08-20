#include "port_state.h"

struct slide_silhouettes_state {
	struct cpu_register_state registers;
	port_u8 textbox_id;
};

/* Port of the SlidePlayerAndEnemySilhouettesOnScreen setup through the
 * DisplayTextBoxID call boundary. */
__attribute__((noinline, used)) void
port_slide_player_enemy_silhouettes(struct slide_silhouettes_state *state)
{
	state->registers.a = 1;
	state->textbox_id = state->registers.a;
}
