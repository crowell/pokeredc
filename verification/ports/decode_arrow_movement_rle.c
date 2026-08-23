#include "port_state.h"

void port_decode_rle_list(struct decode_rle_list_state *state,
	port_u8 *memory);

enum {
	SIMULATED_JOYPAD_STATES_END = 0xccd3,
};

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

static void
set_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

/* Return zero for the terminator, one to scan again, and two for a match. */
__attribute__((noinline, used)) port_u8
port_decode_arrow_movement_rle_step(
	struct decode_arrow_movement_rle_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->rle.fill.registers;
	port_u16 hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	port_u8 old_a;

	registers->a = state->fetched_y;
	hl++;
	set_hl(registers, hl);
	registers->f = compare_flags(registers->a, 0xff);
	if (registers->a == 0xff)
		return 0;
	registers->f = compare_flags(registers->a, registers->b);
	if (registers->a != registers->b) {
		set_hl(registers, (port_u16)(hl + 3));
		return 1;
	}
	registers->a = state->fetched_x;
	hl++;
	set_hl(registers, hl);
	registers->f = compare_flags(registers->a, registers->c);
	if (registers->a != registers->c) {
		set_hl(registers, (port_u16)(hl + 2));
		return 1;
	}
	registers->a = state->fetched_pointer_low;
	hl++;
	registers->d = state->fetched_pointer_high;
	registers->e = registers->a;
	set_hl(registers, SIMULATED_JOYPAD_STATES_END);
	port_decode_rle_list(&state->rle, memory);
	old_a = registers->a;
	registers->a--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
	state->simulated_joypad_states_index = registers->a;
	return 2;
}

/* Port of DecodeArrowMovementRLE in home/map_objects.asm. */
__attribute__((noinline, used)) void
port_decode_arrow_movement_rle(
	struct decode_arrow_movement_rle_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->rle.fill.registers;
	port_u16 hl;
	port_u8 result;

	do {
		hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
		state->fetched_y = memory[hl];
		if (state->fetched_y != 0xff && state->fetched_y == registers->b) {
			state->fetched_x = memory[(port_u16)(hl + 1)];
			if (state->fetched_x == registers->c) {
				state->fetched_pointer_low = memory[(port_u16)(hl + 2)];
				state->fetched_pointer_high = memory[(port_u16)(hl + 3)];
			}
		}
		result = port_decode_arrow_movement_rle_step(state, memory);
	} while (result == 1);
}
