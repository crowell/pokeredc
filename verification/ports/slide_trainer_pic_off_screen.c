#include "port_state.h"

struct slide_trainer_pic_state {
	struct cpu_register_state registers;
	port_u8 slide_amount;
};

/* Port of SlideTrainerPicOffScreen setup through the first row loop. */
__attribute__((noinline, used)) void
port_slide_trainer_pic_off_screen(struct slide_trainer_pic_state *state)
{
	state->slide_amount = state->registers.a;
	state->registers.c = state->registers.a;
	state->registers.b = 7;
}
