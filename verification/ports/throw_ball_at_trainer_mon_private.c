#include "port_state.h"

struct throw_ball_at_trainer_mon_private_state {
	struct cpu_register_state registers;
	port_u8 animation_id;
};

/* Port of ThrowBallAtTrainerMon through MoveAnimation dispatch. */
__attribute__((noinline, used)) void
port_throw_ball_at_trainer_mon_private(
	struct throw_ball_at_trainer_mon_private_state *state)
{
	state->registers.a = 8;
	state->animation_id = 8;
}
