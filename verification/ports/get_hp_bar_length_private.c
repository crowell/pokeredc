#include "port_state.h"

struct get_hp_bar_length_private_state {
	struct cpu_register_state registers;
	port_u8 math[4];
	port_u8 divisor;
	port_u8 buffer[5];
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
};

void port_multiply_wrapper(struct multiply_wrapper_state *state);
void port_divide_wrapper(struct divide_wrapper_state *state);

static void
hp_srl(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	*value >>= 1;
	registers->f = (port_u8)((*value == 0 ? PORT_FLAG_Z : 0) |
	    (old & 1 ? PORT_FLAG_C : 0));
}

static void
hp_rr(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = (registers->f & PORT_FLAG_C) != 0;

	*value = (port_u8)((old >> 1) | (carry ? 0x80 : 0));
	registers->f = (port_u8)((*value == 0 ? PORT_FLAG_Z : 0) |
	    (old & 1 ? PORT_FLAG_C : 0));
}

static void
hp_and_a(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
hp_multiply(struct get_hp_bar_length_private_state *state)
{
	struct multiply_wrapper_state multiply;
	port_u8 index;

	multiply.multiply.registers = state->registers;
	for (index = 0; index < 4; index++)
		multiply.multiply.product[index] = state->math[index];
	multiply.multiply.multiplier = state->divisor;
	for (index = 0; index < 4; index++)
		multiply.multiply.buffer[index] = state->buffer[index + 1];
	multiply.loaded_rom_bank = state->loaded_rom_bank;
	multiply.mapper_bank = state->mapper_bank;
	port_multiply_wrapper(&multiply);
	state->registers = multiply.multiply.registers;
	for (index = 0; index < 4; index++)
		state->math[index] = multiply.multiply.product[index];
	state->divisor = multiply.multiply.multiplier;
	for (index = 0; index < 4; index++)
		state->buffer[index + 1] = multiply.multiply.buffer[index];
	state->loaded_rom_bank = multiply.loaded_rom_bank;
	state->mapper_bank = multiply.mapper_bank;
}

static void
hp_divide(struct get_hp_bar_length_private_state *state)
{
	struct divide_wrapper_state divide;
	port_u8 index;

	divide.divide.registers = state->registers;
	for (index = 0; index < 4; index++)
		divide.divide.dividend[index] = state->math[index];
	divide.divide.divisor = state->divisor;
	for (index = 0; index < 5; index++)
		divide.divide.buffer[index] = state->buffer[index];
	divide.loaded_rom_bank = state->loaded_rom_bank;
	divide.mapper_bank = state->mapper_bank;
	port_divide_wrapper(&divide);
	state->registers = divide.divide.registers;
	for (index = 0; index < 4; index++)
		state->math[index] = divide.divide.dividend[index];
	state->divisor = divide.divide.divisor;
	for (index = 0; index < 5; index++)
		state->buffer[index] = divide.divide.buffer[index];
	state->loaded_rom_bank = divide.loaded_rom_bank;
	state->mapper_bank = divide.mapper_bank;
}

/* Port of the complete GetHPBarLength function. */
__attribute__((noinline, used)) void
port_get_hp_bar_length_private(struct get_hp_bar_length_private_state *state)
{
	struct cpu_register_state *registers = &state->registers;
	port_u8 saved_h = registers->h;
	port_u8 saved_l = registers->l;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	registers->h = 0xff;
	registers->l = 0x96;
	state->math[1] = registers->a;
	registers->l++;
	registers->a = registers->b;
	state->math[2] = registers->a;
	registers->l++;
	registers->a = registers->c;
	state->math[3] = registers->a;
	registers->l++;
	state->divisor = 0x30;
	hp_multiply(state);

	registers->a = registers->d;
	hp_and_a(registers);
	if (registers->a != 0) {
		hp_srl(registers, &registers->d);
		hp_rr(registers, &registers->e);
		hp_srl(registers, &registers->d);
		hp_rr(registers, &registers->e);
		registers->a = state->math[2];
		registers->b = registers->a;
		registers->a = state->math[3];
		hp_srl(registers, &registers->b);
		hp_rr(registers, &registers->a);
		hp_srl(registers, &registers->b);
		hp_rr(registers, &registers->a);
		state->math[3] = registers->a;
		registers->a = registers->b;
		state->math[2] = registers->a;
	}
	registers->a = registers->e;
	state->divisor = registers->a;
	registers->b = 4;
	hp_divide(state);
	registers->a = state->math[3];
	registers->e = registers->a;
	registers->h = saved_h;
	registers->l = saved_l;
	hp_and_a(registers);
	if (registers->a == 0)
		registers->e = 1;
}
