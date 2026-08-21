#include "port_state.h"

struct cinnabar_quiz_question_private_state {
	struct cpu_register_state registers;
	port_u8 gym_gate_answer;
	port_u8 current_menu_item;
};

/* Port of CinnabarGymQuiz_AskQuestion through answer comparison. */
__attribute__((noinline, used)) void
port_cinnabar_gym_quiz_ask_question_private(
	struct cinnabar_quiz_question_private_state *state)
{
	state->registers.c = state->gym_gate_answer;
	state->registers.a = state->current_menu_item;
}
