#include "port_state.h"

/* Ports of true no-op routines whose assembly bodies contain only RET. */
__attribute__((noinline, used)) void
port_empty_func(struct cpu_register_state *state)
{
	(void)state;
}

__attribute__((noinline, used)) void
port_empty_func3(struct cpu_register_state *state)
{
	(void)state;
}

__attribute__((noinline, used)) void
port_ai_move_choice_modification4(struct cpu_register_state *state)
{
	(void)state;
}

/* Debug support is compiled out in the retail build, leaving only RET. */
__attribute__((noinline, used)) void
port_debug_pressed_or_held_b(struct cpu_register_state *state)
{
	(void)state;
}
