#include "port_state.h"

static port_u8
npc_direction(port_u8 direction)
{
	if ((direction & 8) != 0)
		return 0;
	if ((direction & 4) != 0)
		return 4;
	if ((direction & 2) != 0)
		return 12;
	return 8;
}

static void
npc_addresses(const struct make_npc_face_state *state, port_u16 address[9])
{
	port_u8 status = state->memory[0];
	port_u8 direction = state->memory[1];
	port_u8 offset = state->memory[2];
	port_u16 initial_hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 enabled = (status & 0x20) == 0;
	port_u8 offset_after_res = offset;
	port_u8 direction_after_res = direction;
	port_u8 facing;
	port_u16 shell_facing;
	port_u8 final_offset;
	port_u16 animation;
	port_u16 update_facing;

	if (enabled && initial_hl == 0xffda)
		offset_after_res &= 0x7f;
	if (enabled && initial_hl == 0xd52a)
		direction_after_res &= 0x7f;
	facing = npc_direction(direction_after_res);
	shell_facing = (port_u16)(((port_u16)state->registers.h << 8) |
		(port_u8)(offset_after_res + 9));
	final_offset = offset_after_res;
	if (enabled && shell_facing == 0xffda)
		final_offset = facing;
	animation = (port_u16)(0xc100 | (port_u8)(final_offset + 8));
	update_facing = (port_u16)(animation + 1);

	address[0] = 0xd72d;
	address[1] = 0xd52a;
	address[2] = 0xffda;
	address[3] = 0xff93;
	address[4] = initial_hl;
	address[5] = shell_facing;
	address[6] = animation;
	address[7] = update_facing;
	address[8] = (port_u16)((update_facing & 0xff00) |
		(port_u8)(final_offset + 2));
}

static port_u8
npc_read(const struct make_npc_face_state *state, const port_u16 address[9],
	port_u16 target)
{
	port_u8 value = 0;
	port_u8 index;

	for (index = 0; index < 9; index++) {
		port_u8 mask = (port_u8)-(address[index] == target);

		value = (port_u8)((value & (port_u8)~mask) |
			(state->memory[index] & mask));
	}
	return value;
}

static void
npc_write(struct make_npc_face_state *state, const port_u16 address[9],
	port_u16 target, port_u8 value)
{
	port_u8 index;

	for (index = 0; index < 9; index++) {
		port_u8 mask = (port_u8)-(address[index] == target);

		state->memory[index] = (port_u8)(
			(state->memory[index] & (port_u8)~mask) | (value & mask));
	}
}

static void
npc_bit(struct cpu_register_state *registers, port_u8 bit)
{
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_H;
	if ((registers->a & (1 << bit)) == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
npc_add(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

/* Port of MakeNPCFacePlayer in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_make_npc_face_player(struct make_npc_face_state *state)
{
	port_u16 address[9];
	port_u16 hl;
	port_u8 enabled;

	npc_addresses(state, address);
	state->registers.a = npc_read(state, address, 0xd72d);
	npc_bit(&state->registers, 5);
	enabled = (state->registers.a & 0x20) == 0;
	if (enabled) {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		npc_write(state, address, hl,
			(port_u8)(npc_read(state, address, hl) & 0x7f));
		state->registers.a = npc_read(state, address, 0xd52a);
		npc_bit(&state->registers, 3);
		if ((state->registers.a & 8) != 0)
			state->registers.c = 0;
		else {
			npc_bit(&state->registers, 2);
			if ((state->registers.a & 4) != 0)
				state->registers.c = 4;
			else {
				npc_bit(&state->registers, 1);
				state->registers.c = (state->registers.a & 2) != 0 ? 12 : 8;
			}
		}
		state->registers.a = npc_read(state, address, 0xffda);
		npc_add(&state->registers, 9);
		state->registers.l = state->registers.a;
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		npc_write(state, address, hl, state->registers.c);
	}

	state->registers.h = 0xc1;
	state->registers.a = npc_read(state, address, 0xffda);
	npc_add(&state->registers, 8);
	state->registers.l = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	npc_write(state, address, hl, 0);

	state->registers.h = 0xc1;
	state->registers.a = npc_read(state, address, 0xffda);
	npc_add(&state->registers, 8);
	state->registers.l = state->registers.a;
	state->registers.a = npc_read(state, address,
		(port_u16)(((port_u16)state->registers.h << 8) | state->registers.l));
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = state->registers.a;
	state->registers.a = npc_read(state, address, hl);
	npc_add(&state->registers, state->registers.b);
	state->registers.b = state->registers.a;
	state->registers.a = npc_read(state, address, 0xff93);
	npc_add(&state->registers, state->registers.b);
	state->registers.b = state->registers.a;
	state->registers.a = npc_read(state, address, 0xffda);
	npc_add(&state->registers, 2);
	state->registers.l = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	npc_write(state, address, hl, state->registers.b);
}
