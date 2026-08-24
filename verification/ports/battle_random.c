#include "port_state.h"

__attribute__((noinline, used)) void
port_random_generate(struct random_generate_state *state);

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of BattleRandom in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_battle_random(struct battle_random_state *state)
{
	port_u8 index;
	port_u8 next_index;
	port_u8 value;
	port_u8 i;

	state->random.registers.a = state->link_state;
	state->random.registers.f = compare_flags(state->link_state, 4);
	if (state->link_state != 4) {
		port_random_generate(&state->random);
		return;
	}

	index = state->list_index;
	next_index = (port_u8)(index + 1);
	state->list_index = next_index;
	value = state->random_numbers[index];
	state->random.registers.a = value;
	state->random.registers.f = compare_flags(next_index, 9);
	if (next_index < 9)
		return;

	state->list_index = 0;
	for (i = 0; i < 9; ++i) {
		value = state->random_numbers[i];
		state->random_numbers[i] = (port_u8)(value * 5u + 1u);
	}
}
