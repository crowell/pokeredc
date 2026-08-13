#include "port_state.h"

static port_u16
moving_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
moving_inc_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->a++;
	registers->f = carry;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
moving_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;
	port_u8 carry = registers->f & PORT_FLAG_C;

	registers->c--;
	registers->f = carry | PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
moving_and(struct cpu_register_state *registers, port_u8 value)
{
	registers->a &= value;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
moving_cp(struct cpu_register_state *registers, port_u8 right)
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

/* Returns 0 for RET, 1 for right water, 2 for left water, or 3 for flower. */
__attribute__((noinline, used)) port_u8
port_update_moving_bg_tiles_setup(struct moving_bg_tiles_state *state)
{
	state->registers.a = state->tile_animations;
	moving_and(&state->registers, 0xff);
	if (state->registers.a == 0)
		return 0;
	state->registers.a = state->counter1;
	moving_inc_a(&state->registers);
	state->counter1 = state->registers.a;
	moving_cp(&state->registers, 20);
	if (state->registers.a < 20)
		return 0;
	moving_cp(&state->registers, 21);
	if (state->registers.a == 21)
		return 3;
	state->registers.h = 0x91;
	state->registers.l = 0x40;
	state->registers.c = 16;
	state->registers.a = state->counter2;
	moving_inc_a(&state->registers);
	moving_and(&state->registers, 7);
	state->counter2 = state->registers.a;
	moving_and(&state->registers, 4);
	state->left = state->registers.a != 0;
	return state->left ? 2 : 1;
}

/* Returns 1 to rotate another byte or 0 to run the water completion. */
__attribute__((noinline, used)) port_u8
port_update_moving_bg_tiles_water_step(struct moving_bg_tiles_state *state)
{
	port_u8 value = state->fetched;
	port_u16 hl = moving_pair(state->registers.h, state->registers.l);

	state->registers.a = state->left
		? (port_u8)((value << 1) | (value >> 7))
		: (port_u8)((value >> 1) | (value << 7));
	state->registers.f = state->left
		? (port_u8)((value >> 7) ? PORT_FLAG_C : 0)
		: (port_u8)((value & 1) ? PORT_FLAG_C : 0);
	state->written = state->registers.a;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	moving_dec_c(&state->registers);
	return state->registers.c == 0 ? 0 : 1;
}

__attribute__((noinline, used)) void
port_update_moving_bg_tiles_water_done(struct moving_bg_tiles_state *state)
{
	port_u8 value;

	state->registers.a = state->tile_animations;
	value = state->registers.a;
	state->registers.a = (port_u8)((value >> 1) | (value << 7));
	state->registers.f = value & 1 ? PORT_FLAG_C : 0;
	if ((value & 1) == 0)
		return;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->counter1 = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_update_moving_bg_tiles_flower_setup(struct moving_bg_tiles_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->counter1 = state->registers.a;
	state->registers.a = state->counter2;
	moving_and(&state->registers, 3);
	moving_cp(&state->registers, 2);
	state->registers.h = 0x1f;
	if (state->registers.a < 2)
		state->registers.l = 0x19;
	else if (state->registers.a == 2)
		state->registers.l = 0x29;
	else
		state->registers.l = 0x39;
	state->registers.d = 0x90;
	state->registers.e = 0x30;
	state->registers.c = 16;
	return 1;
}

/* Returns 1 to copy another byte or 0 after the sixteenth byte. */
__attribute__((noinline, used)) port_u8
port_update_moving_bg_tiles_flower_step(struct moving_bg_tiles_state *state)
{
	port_u16 hl = moving_pair(state->registers.h, state->registers.l);
	port_u16 de = moving_pair(state->registers.d, state->registers.e);

	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	state->write_h = state->registers.d;
	state->write_l = state->registers.e;
	de++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	moving_dec_c(&state->registers);
	return state->registers.c == 0 ? 0 : 1;
}

/* Port of UpdateMovingBgTiles in home/vcopy.asm. */
__attribute__((noinline, used)) void
port_update_moving_bg_tiles(struct moving_bg_tiles_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_update_moving_bg_tiles_setup(state);
	port_u16 address;

	if (continuation == 0)
		return;
	if (continuation == 3) {
		continuation = port_update_moving_bg_tiles_flower_setup(state);
		while (continuation != 0) {
			address = moving_pair(state->registers.h, state->registers.l);
			state->fetched = memory[address];
			continuation =
				port_update_moving_bg_tiles_flower_step(state);
			address = moving_pair(state->write_h, state->write_l);
			memory[address] = state->written;
		}
		return;
	}
	while (continuation != 0) {
		address = moving_pair(state->registers.h, state->registers.l);
		state->fetched = memory[address];
		continuation = port_update_moving_bg_tiles_water_step(state);
		address = moving_pair(state->write_h, state->write_l);
		memory[address] = state->written;
	}
	port_update_moving_bg_tiles_water_done(state);
}
