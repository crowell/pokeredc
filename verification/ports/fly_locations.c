#include "port_state.h"

static port_u16
fly_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
fly_inc(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)++;
	registers->f = carry;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
fly_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)--;
	registers->f = carry | PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

__attribute__((noinline, used)) port_u8
port_build_fly_locations_setup(struct fly_locations_state *state)
{
	port_u16 hl = 0xcd3d;

	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->visited_low;
	state->registers.e = state->registers.a;
	state->registers.a = state->visited_high;
	state->registers.d = state->registers.a;
	state->registers.b = 0;
	state->registers.c = 11;
	return 1;
}

/* Returns 1 to emit another city or 0 before the final terminator write. */
__attribute__((noinline, used)) port_u8
port_build_fly_locations_step(struct fly_locations_state *state)
{
	port_u8 old_d = state->registers.d;
	port_u8 old_e = state->registers.e;
	port_u8 carry_d = old_d & 1;
	port_u16 hl;

	state->registers.d >>= 1;
	state->registers.f = state->registers.d == 0 ? PORT_FLAG_Z : 0;
	if (carry_d)
		state->registers.f |= PORT_FLAG_C;
	state->registers.e = (port_u8)((old_e >> 1) | (carry_d << 7));
	state->registers.f = state->registers.e == 0 ? PORT_FLAG_Z : 0;
	if (old_e & 1)
		state->registers.f |= PORT_FLAG_C;
	state->registers.a = 0xfe;
	if (old_e & 1)
		state->registers.a = state->registers.b;
	state->written = state->registers.a;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
	hl = (port_u16)(fly_pair(state->registers.h, state->registers.l) + 1);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	fly_inc(&state->registers, &state->registers.b);
	fly_dec(&state->registers, &state->registers.c);
	return state->registers.c == 0 ? 0 : 1;
}

__attribute__((noinline, used)) void
port_build_fly_locations_finish(struct fly_locations_state *state)
{
	state->written = 0xff;
	state->write_h = state->registers.h;
	state->write_l = state->registers.l;
}

/* Port of BuildFlyLocationsList in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_build_fly_locations_list(struct fly_locations_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_build_fly_locations_setup(state);
	port_u16 address = fly_pair(state->write_h, state->write_l);

	memory[address] = state->written;
	while (continuation != 0) {
		continuation = port_build_fly_locations_step(state);
		address = fly_pair(state->write_h, state->write_l);
		memory[address] = state->written;
	}
	port_build_fly_locations_finish(state);
	address = fly_pair(state->write_h, state->write_l);
	memory[address] = state->written;
}
