#include "port_state.h"

__attribute__((noinline, used)) void
port_show_object_begin(struct show_object_state *state)
{
	state->registers.h = 0xd5;
	state->registers.l = 0xa6;
	state->registers.a = state->toggleable_object_index;
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	state->stage = 1;
}

/* Port of ShowObject/ShowObject2 in engine/overworld/toggleable_objects.asm. */
__attribute__((noinline, used)) void
port_show_object(struct show_object_state *state,
	const struct cpu_register_state callbacks[2],
	const port_u8 callback_indices[2])
{
	port_show_object_begin(state);
	/* ToggleableObjectFlagAction returns before the UpdateSprites tail jump. */
	state->registers = callbacks[0];
	state->toggleable_object_index = callback_indices[0];
	state->stage = 2;
	state->registers = callbacks[1];
	state->toggleable_object_index = callback_indices[1];
	state->stage = 3;
}
