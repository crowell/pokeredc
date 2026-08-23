#include "port_state.h"

void port_get_pointer_within_sprite_state_data1(
	struct cpu_register_state *state, const port_u8 *memory);

#define H_SPRITE_DATA_OFFSET 0xff8bu
#define H_SPRITE_FACING_DIRECTION 0xff8du
#define SPRITE_STATE_DATA1_FACING_DIRECTION 9u

__attribute__((noinline, used)) void
port_set_sprite_facing_direction(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 address;

	state->a = SPRITE_STATE_DATA1_FACING_DIRECTION;
	memory[H_SPRITE_DATA_OFFSET] = state->a;
	port_get_pointer_within_sprite_state_data1(state, memory);
	state->a = memory[H_SPRITE_FACING_DIRECTION];
	address = (port_u16)(((port_u16)state->h << 8) | state->l);
	memory[address] = state->a;
}
