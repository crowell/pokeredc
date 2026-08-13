#include "port_state.h"

static port_u8
slot_match_compare(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
	return left == right;
}

/* Port of SlotMachine_FindWheel1Wheel2Matches in engine/slots/slot_machine.asm. */
__attribute__((noinline, used)) void
port_slot_machine_find_wheel1_wheel2_matches(
	struct slot_wheel_match_state *state)
{
	state->registers.h = 0xcd;
	state->registers.l = 0x41;
	state->registers.d = 0xcd;
	state->registers.e = 0x44;
	state->registers.a = state->wheel2[0];
	if (slot_match_compare(&state->registers, state->wheel1[0]))
		return;
	state->registers.e++;
	state->registers.a = state->wheel2[1];
	if (slot_match_compare(&state->registers, state->wheel1[0]))
		return;
	state->registers.l++;
	if (slot_match_compare(&state->registers, state->wheel1[1]))
		return;
	state->registers.l++;
	if (slot_match_compare(&state->registers, state->wheel1[2]))
		return;
	state->registers.e++;
	state->registers.a = state->wheel2[2];
	if (slot_match_compare(&state->registers, state->wheel1[2]))
		return;
	state->registers.e--;
	state->registers.e--;
}
