#include "port_state.h"

struct print_send_out_state {
	struct cpu_register_state registers;
	port_u8 current_hp_low;
	port_u8 current_hp_high;
};

#define W_TEXT_BOX_ID 0xd125u
#define W_ENEMY_MON_MAX_HP 0xcff4u
#define W_LAST_SWITCH_IN_ENEMY_MON_HP 0xcce3u
#define H_PRODUCT 0xff95u
#define H_MULTIPLIER 0xff99u
#define H_BUFFER 0xff9bu
#define H_DIVISOR 0xff99u
#define H_DIVIDE_BUFFER 0xff9au
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_multiply_wrapper(struct multiply_wrapper_state *);
void port_divide_wrapper(struct divide_wrapper_state *);

static void
call_multiply(struct cpu_register_state *registers, port_u8 *memory)
{
	struct multiply_wrapper_state multiply = {0};
	port_u8 i;
	multiply.multiply.registers = *registers;
	for (i = 0; i < 4; ++i)
		multiply.multiply.product[i] = memory[H_PRODUCT + i];
	multiply.multiply.multiplier = memory[H_MULTIPLIER];
	for (i = 0; i < 4; ++i)
		multiply.multiply.buffer[i] = memory[H_BUFFER + i];
	multiply.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	multiply.mapper_bank = memory[R_ROMB];
	port_multiply_wrapper(&multiply);
	*registers = multiply.multiply.registers;
	for (i = 0; i < 4; ++i)
		memory[H_PRODUCT + i] = multiply.multiply.product[i];
	memory[H_MULTIPLIER] = multiply.multiply.multiplier;
	for (i = 0; i < 4; ++i)
		memory[H_BUFFER + i] = multiply.multiply.buffer[i];
	memory[H_LOADED_ROM_BANK] = multiply.loaded_rom_bank;
	memory[R_ROMB] = multiply.mapper_bank;
}

static void
call_divide(struct cpu_register_state *registers, port_u8 *memory)
{
	struct divide_wrapper_state divide = {0};
	port_u8 i;
	divide.divide.registers = *registers;
	for (i = 0; i < 4; ++i)
		divide.divide.dividend[i] = memory[H_PRODUCT + i];
	divide.divide.divisor = memory[H_DIVISOR];
	for (i = 0; i < 5; ++i)
		divide.divide.buffer[i] = memory[H_DIVIDE_BUFFER + i];
	divide.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	divide.mapper_bank = memory[R_ROMB];
	port_divide_wrapper(&divide);
	*registers = divide.divide.registers;
	for (i = 0; i < 4; ++i)
		memory[H_PRODUCT + i] = divide.divide.dividend[i];
	memory[H_DIVISOR] = divide.divide.divisor;
	for (i = 0; i < 5; ++i)
		memory[H_DIVIDE_BUFFER + i] = divide.divide.buffer[i];
	memory[H_LOADED_ROM_BANK] = divide.loaded_rom_bank;
	memory[R_ROMB] = divide.mapper_bank;
}

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;
	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of the PrintSendOutMonMessage entry through the GoText branch. */
__attribute__((noinline, used)) void
port_print_send_out_mon_message(struct print_send_out_state *state,
	port_u8 *memory)
{
	port_u8 value = state->current_hp_low | state->current_hp_high;

	state->registers.a = value;
	state->registers.f = value == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0x4e;
	state->registers.l = 0xae;
	if (value == 0) {
		port_print_text(&state->registers, memory);
		return;
	}

	/* The nonzero path stores the current HP as a big-endian 24-bit
	 * multiplicand, then computes (current HP * 25) / (max HP / 4). */
	memory[W_LAST_SWITCH_IN_ENEMY_MON_HP] = state->current_hp_low;
	memory[W_LAST_SWITCH_IN_ENEMY_MON_HP + 1u] = state->current_hp_high;
	memory[H_PRODUCT] = 0;
	memory[H_PRODUCT + 1u] = 0;
	memory[H_PRODUCT + 2u] = state->current_hp_low;
	memory[H_PRODUCT + 3u] = state->current_hp_high;
	memory[H_MULTIPLIER] = 25;
	for (port_u8 i = 0; i < 4; ++i)
		memory[H_BUFFER + i] = 0;
	call_multiply(&state->registers, memory);

	{
		port_u16 max_hp = (port_u16)(((port_u16)memory[W_ENEMY_MON_MAX_HP] << 8) |
			memory[W_ENEMY_MON_MAX_HP + 1u]);
		port_u8 divisor = (port_u8)(max_hp >> 2);
		state->registers.h = (port_u8)(W_ENEMY_MON_MAX_HP >> 8);
		state->registers.l = (port_u8)W_ENEMY_MON_MAX_HP;
		state->registers.a = memory[W_ENEMY_MON_MAX_HP];
		state->registers.b = memory[W_ENEMY_MON_MAX_HP + 1u];
		state->registers.a = (port_u8)((state->registers.a >> 1) |
			((state->registers.b & 1u) << 7));
		state->registers.b >>= 1;
		state->registers.a = (port_u8)((state->registers.a >> 1) |
			((state->registers.b & 1u) << 7));
		state->registers.b >>= 1;
		state->registers.a = divisor;
		state->registers.b = 4;
		memory[H_DIVISOR] = divisor;
		for (port_u8 i = 0; i < 5; ++i)
			memory[H_DIVIDE_BUFFER + i] = 0;
		call_divide(&state->registers, memory);
	}

	{
		port_u8 percentage = memory[H_PRODUCT + 3u];
		port_u16 text = 0x4ec3u;
		port_u8 threshold = 10;
		if (percentage >= 70) {
			text = 0x4eaeu;
			threshold = 70;
		} else if (percentage >= 40) {
			text = 0x4eb5u;
			threshold = 40;
		} else if (percentage >= 10) {
			text = 0x4ebcu;
		}
		state->registers.a = percentage;
		state->registers.f = compare_flags(percentage, threshold);
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
		port_print_text(&state->registers, memory);
	}
}
