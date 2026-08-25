#include "port_state.h"

void port_battle_random(struct battle_random_state *state);
void port_multiply_wrapper(struct multiply_wrapper_state *state);
void port_divide_wrapper(struct divide_wrapper_state *state);

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

__attribute__((noinline, used)) port_u8
port_randomize_damage_begin(struct randomize_damage_state *state)
{
	struct cpu_register_state *registers = &state->battle.random.registers;

	registers->h = 0xd0;
	registers->l = 0xd7;
	registers->a = state->damage[0];
	registers->l++;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (registers->a == 0) {
		registers->a = state->damage[1];
		registers->f = compare_flags(registers->a, 2);
		if (registers->a < 2)
			return 1;
	}

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	state->product[1] = registers->a;
	registers->l--;
	registers->a = state->damage[0];
	registers->l++;
	state->product[2] = registers->a;
	registers->a = state->damage[1];
	state->product[3] = registers->a;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_randomize_damage_random_step(struct randomize_damage_state *state)
{
	struct cpu_register_state *registers = &state->battle.random.registers;
	port_u8 value;

	port_battle_random(&state->battle);
	value = registers->a;
	registers->a = (port_u8)((value >> 1) | (value << 7));
	registers->f = (value & 1) ? PORT_FLAG_C : 0;
	registers->f = compare_flags(registers->a, 217);
	return registers->a >= 217;
}

static void
randomize_damage_multiply(struct randomize_damage_state *state)
{
	struct multiply_wrapper_state multiply;
	port_u8 i;

	multiply.multiply.registers = state->battle.random.registers;
	for (i = 0; i < 4; ++i)
		multiply.multiply.product[i] = state->product[i];
	multiply.multiply.multiplier = state->multiplier;
	for (i = 0; i < 4; ++i)
		multiply.multiply.buffer[i] = state->divide_buffer[i + 1];
	multiply.loaded_rom_bank = state->battle.random.loaded_bank;
	multiply.mapper_bank = state->battle.random.rom_bank;
	port_multiply_wrapper(&multiply);
	state->battle.random.registers = multiply.multiply.registers;
	for (i = 0; i < 4; ++i)
		state->product[i] = multiply.multiply.product[i];
	state->multiplier = multiply.multiply.multiplier;
	for (i = 0; i < 4; ++i)
		state->divide_buffer[i + 1] = multiply.multiply.buffer[i];
	state->battle.random.loaded_bank = multiply.loaded_rom_bank;
	state->battle.random.rom_bank = multiply.mapper_bank;
}

static void
randomize_damage_divide(struct randomize_damage_state *state)
{
	struct divide_wrapper_state divide;
	port_u8 i;

	divide.divide.registers = state->battle.random.registers;
	for (i = 0; i < 4; ++i)
		divide.divide.dividend[i] = state->product[i];
	divide.divide.divisor = state->multiplier;
	for (i = 0; i < 5; ++i)
		divide.divide.buffer[i] = state->divide_buffer[i];
	divide.loaded_rom_bank = state->battle.random.loaded_bank;
	divide.mapper_bank = state->battle.random.rom_bank;
	port_divide_wrapper(&divide);
	state->battle.random.registers = divide.divide.registers;
	for (i = 0; i < 4; ++i)
		state->product[i] = divide.divide.dividend[i];
	state->multiplier = divide.divide.divisor;
	for (i = 0; i < 5; ++i)
		state->divide_buffer[i] = divide.divide.buffer[i];
	state->battle.random.loaded_bank = divide.loaded_rom_bank;
	state->battle.random.rom_bank = divide.mapper_bank;
}

__attribute__((noinline, used)) void
port_randomize_damage_finish(struct randomize_damage_state *state)
{
	struct cpu_register_state *registers = &state->battle.random.registers;

	state->multiplier = registers->a;
	randomize_damage_multiply(state);
	registers->a = 255;
	state->multiplier = registers->a;
	registers->b = 4;
	randomize_damage_divide(state);
	registers->a = state->product[2];
	registers->h = 0xd0;
	registers->l = 0xd7;
	state->damage[0] = registers->a;
	registers->l++;
	registers->a = state->product[3];
	state->damage[1] = registers->a;
}

/* Port of RandomizeDamage in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_randomize_damage(struct randomize_damage_state *state)
{
	if (port_randomize_damage_begin(state))
		return;
	while (!port_randomize_damage_random_step(state))
		;
	port_randomize_damage_finish(state);
}
