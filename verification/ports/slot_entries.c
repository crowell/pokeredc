#include "port_state.h"

static void
slot_ball_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) |
		registers->l);
	port_u16 result = (port_u16)(left + right);
	port_u8 saved_z = registers->f & PORT_FLAG_Z;

	registers->f = saved_z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if ((unsigned long)left + right > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

static void
slot_ball_store(struct slot_ball_tiles_state *state, port_u8 index)
{
	port_u16 address = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->destination[index] = state->registers.a;
	if (address == 0xd08a)
		state->new_tile = state->registers.a;
}

static void
slot_ball_update_parts(struct cpu_register_state *registers, port_u8 *new_tile,
	port_u8 *destination)
{
	port_u8 old_a;

	registers->a = *new_tile;
	destination[0] = registers->a;
	registers->b = 0;
	registers->c = 13;
	slot_ball_add_hl(registers, 13);
	destination[1] = registers->a;
	registers->c = 7;
	slot_ball_add_hl(registers, 7);
	old_a = registers->a;
	registers->a++;
	registers->f &= PORT_FLAG_C;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
	destination[2] = registers->a;
	registers->c = 13;
	slot_ball_add_hl(registers, 13);
	destination[3] = registers->a;
}

/* Port of SlotMachine_UpdateBallTiles in engine/slots/slot_machine.asm. */
__attribute__((noinline, used)) void
port_slot_machine_update_ball_tiles(struct slot_ball_tiles_state *state)
{
	port_u8 old_a;

	state->registers.a = state->new_tile;
	slot_ball_store(state, 0);
	state->registers.b = 0;
	state->registers.c = 13;
	slot_ball_add_hl(&state->registers, 13);
	slot_ball_store(state, 1);
	state->registers.c = 7;
	slot_ball_add_hl(&state->registers, 7);
	old_a = state->registers.a;
	state->registers.a++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	slot_ball_store(state, 2);
	state->registers.c = 13;
	slot_ball_add_hl(&state->registers, 13);
	slot_ball_store(state, 3);
}

static void
slot_ball_set_hl(struct cpu_register_state *registers, port_u16 address)
{
	registers->h = (port_u8)(address >> 8);
	registers->l = (port_u8)address;
}

#define SLOT_BALL_BEGIN(name, address) \
	__attribute__((noinline, used)) void name( \
		struct slot_ball_cascade_state *state) \
	{ \
		slot_ball_set_hl(&state->registers, address); \
	}

SLOT_BALL_BEGIN(port_slot_machine_update_three_coin_ball_tiles_begin0, 0xc3cb)
SLOT_BALL_BEGIN(port_slot_machine_update_three_coin_ball_tiles_begin1, 0xc46b)
SLOT_BALL_BEGIN(port_slot_machine_update_two_coin_ball_tiles_begin0, 0xc3f3)
SLOT_BALL_BEGIN(port_slot_machine_update_two_coin_ball_tiles_begin1, 0xc443)
SLOT_BALL_BEGIN(port_slot_machine_update_one_coin_ball_tiles_begin, 0xc41b)

static void
slot_ball_one(struct slot_ball_cascade_state *state, port_u8 index)
{
	port_slot_machine_update_one_coin_ball_tiles_begin(state);
	slot_ball_update_parts(&state->registers, &state->new_tile,
		&state->destination[index]);
}

static void
slot_ball_two(struct slot_ball_cascade_state *state, port_u8 index)
{
	port_slot_machine_update_two_coin_ball_tiles_begin0(state);
	slot_ball_update_parts(&state->registers, &state->new_tile,
		&state->destination[index]);
	port_slot_machine_update_two_coin_ball_tiles_begin1(state);
	slot_ball_update_parts(&state->registers, &state->new_tile,
		&state->destination[index + 4]);
	slot_ball_one(state, (port_u8)(index + 8));
}

__attribute__((noinline, used)) void
port_slot_machine_update_one_coin_ball_tiles(
	struct slot_ball_cascade_state *state)
{
	slot_ball_one(state, 0);
}

__attribute__((noinline, used)) void
port_slot_machine_update_two_coin_ball_tiles(
	struct slot_ball_cascade_state *state)
{
	slot_ball_two(state, 0);
}

__attribute__((noinline, used)) void
port_slot_machine_update_three_coin_ball_tiles(
	struct slot_ball_cascade_state *state)
{
	port_slot_machine_update_three_coin_ball_tiles_begin0(state);
	slot_ball_update_parts(&state->registers, &state->new_tile,
		&state->destination[0]);
	port_slot_machine_update_three_coin_ball_tiles_begin1(state);
	slot_ball_update_parts(&state->registers, &state->new_tile,
		&state->destination[4]);
	slot_ball_two(state, 8);
}

__attribute__((noinline, used)) void
port_slot_machine_put_out_lit_balls_begin(
	struct slot_ball_cascade_state *state)
{
	state->registers.a = 0x23;
	state->new_tile = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_slot_machine_light_balls_begin(struct slot_ball_cascade_state *state)
{
	port_u8 old_a;

	state->registers.a = 0x14;
	state->new_tile = state->registers.a;
	state->registers.a = state->bet;
	old_a = state->registers.a;
	state->registers.a--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.a == 0)
		return 1;
	old_a = state->registers.a;
	state->registers.a--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.a == 0 ? 2 : 3;
}

__attribute__((noinline, used)) void
port_slot_machine_put_out_lit_balls(struct slot_ball_cascade_state *state)
{
	port_slot_machine_put_out_lit_balls_begin(state);
	port_slot_machine_update_three_coin_ball_tiles(state);
}

__attribute__((noinline, used)) void
port_slot_machine_light_balls(struct slot_ball_cascade_state *state)
{
	port_u8 count = port_slot_machine_light_balls_begin(state);

	if (count == 1)
		port_slot_machine_update_one_coin_ball_tiles(state);
	else if (count == 2)
		port_slot_machine_update_two_coin_ball_tiles(state);
	else
		port_slot_machine_update_three_coin_ball_tiles(state);
}

static void
slot_wheel_entry(
	struct slot_wheel_entry_state *state,
	port_u16 bc,
	port_u16 de,
	port_u16 hl,
	port_u8 x)
{
	state->registers.b = (port_u8)(bc >> 8);
	state->registers.c = (port_u8)bc;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = x;
	state->base_x = x;
}

__attribute__((noinline, used)) void port_slot_machine_anim_wheel1(struct slot_wheel_entry_state *state) { slot_wheel_entry(state, 0x79e5, 0xcd3e, 0xc300, 0x30); }
__attribute__((noinline, used)) void port_slot_machine_anim_wheel2(struct slot_wheel_entry_state *state) { slot_wheel_entry(state, 0x7a09, 0xcd3f, 0xc330, 0x50); }
__attribute__((noinline, used)) void port_slot_machine_anim_wheel3(struct slot_wheel_entry_state *state) { slot_wheel_entry(state, 0x7a2d, 0xcd40, 0xc360, 0x70); }
