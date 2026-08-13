#include "port_state.h"

/* Port of _EndNPCMovementScript in engine/overworld/auto_movement.asm. */
__attribute__((noinline, used)) void
port_end_npc_movement_script(struct npc_movement_end_state *state)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x30;
	state->status_flags5 &= (port_u8)~0x80;
	state->registers.h = 0xd7;
	state->registers.l = 0x2e;
	state->status_flags4 &= (port_u8)~0x80;
	state->registers.h = 0xd7;
	state->registers.l = 0x36;
	state->movement_flags &= (port_u8)~0x01;
	state->movement_flags &= (port_u8)~0x02;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->script_sprite_offset = 0;
	state->script_pointer_table_num = 0;
	state->script_function_num = 0;
	state->override_simulated_joypad_index = 0;
	state->simulated_joypad_index = 0;
	state->simulated_joypad_end = 0;
}

static void
compare_direction(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_convert_npc_movement_direction_begin(struct movement_direction_state *state)
{
	state->registers.b = state->registers.a;
	state->registers.h = 0x79;
	state->registers.l = 0xd2;
}

/* Returns 0 to continue, 1 for a match, and 2 for the terminator. */
__attribute__((noinline, used)) port_u8
port_convert_npc_movement_direction_step(struct movement_direction_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched_direction;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	compare_direction(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 2;
	compare_direction(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b)
		return 1;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
}

__attribute__((noinline, used)) void
port_convert_npc_movement_direction_load_mask(
	struct movement_direction_state *state)
{
	state->registers.a = state->fetched_mask;
}

/* Port of ConvertNPCMovementDirectionToJoypadMask. */
__attribute__((noinline, used)) void
port_convert_npc_movement_direction_to_joypad_mask(
	struct movement_direction_state *state, const port_u8 *table)
{
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u16 offset = 0;
	port_u8 result;

	port_convert_npc_movement_direction_begin(state);
	for (;;) {
		state->fetched_direction = table[offset];
		result = port_convert_npc_movement_direction_step(state);
		if (result != 0)
			break;
		offset += 2;
	}
	if (result == 1) {
		state->fetched_mask = table[offset + 1];
		port_convert_npc_movement_direction_load_mask(state);
	}
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
