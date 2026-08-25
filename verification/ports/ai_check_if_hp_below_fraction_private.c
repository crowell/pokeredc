#include "port_state.h"

struct ai_check_hp_fraction_private_state {
	struct cpu_register_state registers;
	port_u8 enemy_max_hp_high;
	port_u8 enemy_max_hp_low;
	port_u8 enemy_hp_high;
	port_u8 enemy_hp_low;
	port_u8 dividend[4];
	port_u8 divisor;
	port_u8 buffer[5];
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
};

void port_divide_wrapper(struct divide_wrapper_state *state);

static void
ai_hp_sub(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->a = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
ai_hp_divide(struct ai_check_hp_fraction_private_state *state)
{
	struct divide_wrapper_state divide;
	port_u8 index;

	divide.divide.registers = state->registers;
	for (index = 0; index < 4; index++)
		divide.divide.dividend[index] = state->dividend[index];
	divide.divide.divisor = state->divisor;
	for (index = 0; index < 5; index++)
		divide.divide.buffer[index] = state->buffer[index];
	divide.loaded_rom_bank = state->loaded_rom_bank;
	divide.mapper_bank = state->mapper_bank;
	port_divide_wrapper(&divide);
	state->registers = divide.divide.registers;
	for (index = 0; index < 4; index++)
		state->dividend[index] = divide.divide.dividend[index];
	state->divisor = divide.divide.divisor;
	for (index = 0; index < 5; index++)
		state->buffer[index] = divide.divide.buffer[index];
	state->loaded_rom_bank = divide.loaded_rom_bank;
	state->mapper_bank = divide.mapper_bank;
}

/* Port of the complete AICheckIfHPBelowFraction function. */
__attribute__((noinline, used)) void
port_ai_check_if_hp_below_fraction_private(
	struct ai_check_hp_fraction_private_state *state)
{
	struct cpu_register_state *registers = &state->registers;

	state->divisor = registers->a;
	registers->h = 0xcf;
	registers->l = 0xf4;
	registers->a = state->enemy_max_hp_high;
	registers->l++;
	state->dividend[0] = registers->a;
	registers->a = state->enemy_max_hp_low;
	state->dividend[1] = registers->a;
	registers->b = 2;
	ai_hp_divide(state);
	registers->a = state->dividend[3];
	registers->c = registers->a;
	registers->a = state->dividend[2];
	registers->b = registers->a;
	registers->h = 0xcf;
	registers->l = 0xe7;
	registers->a = state->enemy_hp_low;
	registers->l--;
	registers->e = registers->a;
	registers->a = state->enemy_hp_high;
	registers->d = registers->a;
	registers->a = registers->d;
	ai_hp_sub(registers, registers->b);
	if (registers->a != 0)
		return;
	registers->a = registers->e;
	ai_hp_sub(registers, registers->c);
}
