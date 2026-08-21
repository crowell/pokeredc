#include "port_state.h"

struct scroll_trainer_pic_private_state {
	struct cpu_register_state registers;
	port_u8 enemy_species2;
};

/* Port of _ScrollTrainerPicAfterBattle through palette-command setup. */
__attribute__((noinline, used)) void
port_scroll_trainer_pic_after_battle_private(
	struct scroll_trainer_pic_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.b = 1;
	state->enemy_species2 = 0;
}
