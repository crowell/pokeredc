#include "port_state.h"

static port_u16
screen_address(port_u8 d, port_u8 e, port_u8 index)
{
	switch (index) {
	case 0:
		return (port_u16)(((port_u16)d << 8) | (port_u8)(e + 2));
	case 1:
		return (port_u16)(((port_u16)d << 8) | (port_u8)(e + 4));
	case 2:
		return 0xff92;
	case 3:
		return 0xff91;
	case 4:
		return (port_u16)(((port_u16)d << 8) | (port_u8)(e + 8));
	default:
		return (port_u16)(((port_u16)d << 8) | (port_u8)(e + 9));
	}
}

static port_u8
screen_read(struct sprite_screen_xy_state *state, port_u8 d, port_u8 e,
	port_u16 address)
{
	port_u8 index;

	for (index = 0; index < 6; index++) {
		if (screen_address(d, e, index) == address)
			return state->memory[index];
	}
	return 0;
}

static void
screen_write(struct sprite_screen_xy_state *state, port_u8 d, port_u8 e,
	port_u16 address, port_u8 value)
{
	port_u8 index;

	for (index = 0; index < 6; index++) {
		if (screen_address(d, e, index) == address)
			state->memory[index] = value;
	}
}

static void
screen_inc_e(struct cpu_register_state *registers)
{
	port_u8 old = registers->e;

	registers->e++;
	registers->f &= PORT_FLAG_C;
	if (registers->e == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
screen_add_a(struct cpu_register_state *registers, port_u8 right)
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

static void
screen_and_f0(struct cpu_register_state *registers)
{
	registers->a &= 0xf0;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

/* Port of GetSpriteScreenXY in engine/gfx/sprite_oam.asm. */
__attribute__((noinline, used)) void
port_get_sprite_screen_xy(struct sprite_screen_xy_state *state)
{
	port_u8 initial_d = state->registers.d;
	port_u8 initial_e = state->registers.e;
	port_u16 de;

	screen_inc_e(&state->registers);
	screen_inc_e(&state->registers);
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	state->registers.a = screen_read(state, initial_d, initial_e, de);
	screen_write(state, initial_d, initial_e, 0xff92, state->registers.a);
	screen_inc_e(&state->registers);
	screen_inc_e(&state->registers);
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	state->registers.a = screen_read(state, initial_d, initial_e, de);
	screen_write(state, initial_d, initial_e, 0xff91, state->registers.a);
	state->registers.a = 4;
	screen_add_a(&state->registers, state->registers.e);
	state->registers.e = state->registers.a;
	state->registers.a = screen_read(state, initial_d, initial_e, 0xff92);
	screen_add_a(&state->registers, 4);
	screen_and_f0(&state->registers);
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	screen_write(state, initial_d, initial_e, de, state->registers.a);
	screen_inc_e(&state->registers);
	state->registers.a = screen_read(state, initial_d, initial_e, 0xff91);
	screen_and_f0(&state->registers);
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	screen_write(state, initial_d, initial_e, de, state->registers.a);
}

/* Raw-memory adapter for callers whose sprite-state and HRAM live in the
 * shared PC memory model.  PrepareOAMData always invokes this with D=$c1 and
 * E at the sprite image index (slot + 2), so the six addresses are distinct.
 * The underlying port retains the complete register/flag transition. */
__attribute__((noinline, used)) void
port_get_sprite_screen_xy_memory(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct sprite_screen_xy_state state;
	port_u8 initial_d = registers->d;
	port_u8 initial_e = registers->e;
	port_u8 index;

	state.registers = *registers;
	for (index = 0; index < 6; index++)
		state.memory[index] = memory[screen_address(initial_d, initial_e, index)];
	port_get_sprite_screen_xy(&state);
	*registers = state.registers;
	for (index = 0; index < 6; index++)
		memory[screen_address(initial_d, initial_e, index)] = state.memory[index];
}
