#include "port_state.h"

#define DE_W_ENEMY_MON_BASE_STATS 0xd002u
#define DE_W_ENEMY_MON_BASE_EXP 0xd008u
#define DE_W_PARTY_GAIN_EXP_FLAGS 0xd058u
#define DE_W_TEMP_BYTE_VALUE 0xd11eu
#define DE_H_DIVIDEND 0xff95u
#define DE_H_DIVISOR 0xff99u
#define DE_H_DIVIDE_BUFFER 0xff9au
#define DE_EXP_DATA_LENGTH 7u

void port_divide_wrapper(struct divide_wrapper_state *state);

static void
divide_exp_xor_a(struct cpu_register_state *registers)
{
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
}

static void
divide_exp_srl_b(struct cpu_register_state *registers)
{
	port_u8 old = registers->b;

	registers->b >>= 1;
	registers->f = (port_u8)((registers->b == 0 ? PORT_FLAG_Z : 0) |
	    (old & 1 ? PORT_FLAG_C : 0));
}

static void
divide_exp_adc_d(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 carry = (registers->f & PORT_FLAG_C) != 0;
	port_u16 wide = (port_u16)left + registers->d + carry;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (registers->d & 0x0f) + carry > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
divide_exp_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;

	registers->c--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
divide_exp_cp_two(struct cpu_register_state *registers)
{
	port_u8 value = registers->a;

	registers->f = PORT_FLAG_N;
	if (value == 2)
		registers->f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 2)
		registers->f |= PORT_FLAG_H;
	if (value < 2)
		registers->f |= PORT_FLAG_C;
}

static void
divide_exp_call_divide(struct divide_exp_data_state *state, port_u8 *memory)
{
	struct divide_wrapper_state divide;
	port_u8 index;

	divide.divide.registers = state->registers;
	for (index = 0; index < 4; index++)
		divide.divide.dividend[index] = memory[DE_H_DIVIDEND + index];
	divide.divide.divisor = memory[DE_H_DIVISOR];
	for (index = 0; index < 5; index++)
		divide.divide.buffer[index] = memory[DE_H_DIVIDE_BUFFER + index];
	divide.loaded_rom_bank = state->loaded_rom_bank;
	divide.mapper_bank = state->mapper_bank;
	port_divide_wrapper(&divide);
	state->registers = divide.divide.registers;
	for (index = 0; index < 4; index++)
		memory[DE_H_DIVIDEND + index] = divide.divide.dividend[index];
	memory[DE_H_DIVISOR] = divide.divide.divisor;
	for (index = 0; index < 5; index++)
		memory[DE_H_DIVIDE_BUFFER + index] = divide.divide.buffer[index];
	state->loaded_rom_bank = divide.loaded_rom_bank;
	state->mapper_bank = divide.mapper_bank;
}

/* Port of the complete DivideExpDataByNumMonsGainingExp function. */
__attribute__((noinline, used)) void
port_divide_exp_data_by_num_mons_gaining_exp(
	struct divide_exp_data_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u16 hl;

	registers->a = memory[DE_W_PARTY_GAIN_EXP_FLAGS];
	registers->b = registers->a;
	divide_exp_xor_a(registers);
	registers->c = 8;
	registers->d = 0;
	do {
		divide_exp_xor_a(registers);
		divide_exp_srl_b(registers);
		divide_exp_adc_d(registers);
		registers->d = registers->a;
		divide_exp_dec_c(registers);
	} while (registers->c != 0);
	divide_exp_cp_two(registers);
	if (registers->f & PORT_FLAG_C)
		return;

	memory[DE_W_TEMP_BYTE_VALUE] = registers->a;
	hl = DE_W_ENEMY_MON_BASE_STATS;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->c = DE_W_ENEMY_MON_BASE_EXP + 1u -
	    DE_W_ENEMY_MON_BASE_STATS;
	do {
		divide_exp_xor_a(registers);
		memory[DE_H_DIVIDEND] = registers->a;
		registers->a = memory[hl];
		memory[DE_H_DIVIDEND + 1] = registers->a;
		registers->a = memory[DE_W_TEMP_BYTE_VALUE];
		memory[DE_H_DIVISOR] = registers->a;
		registers->b = 2;
		divide_exp_call_divide(state, memory);
		registers->a = memory[DE_H_DIVIDEND + 3];
		memory[hl] = registers->a;
		hl++;
		registers->h = (port_u8)(hl >> 8);
		registers->l = (port_u8)hl;
		divide_exp_dec_c(registers);
	} while (registers->c != 0);
}
