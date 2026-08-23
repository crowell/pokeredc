#include "port_state.h"

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);
void port_flag_action(struct flag_action_state *state);
void port_is_item_hm(struct accumulator_state *state);

#define W_CUR_ITEM      0xCF91
#define W_IS_KEY_ITEM   0xD124
#define W_BUFFER        0xCEE9
#define KEY_ITEM_FLAGS  0x6799
#define HM01            0xC4
#define FLAG_TEST       0x02

static port_u8
comparison_flags(port_u8 left, port_u8 right)
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

static void
call_is_item_hm(struct cpu_register_state *registers)
{
	struct accumulator_state item = {registers->a, registers->f};

	port_is_item_hm(&item);
	registers->a = item.a;
	registers->f = item.f;
}

__attribute__((noinline, used)) void
port_is_key_item_(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 item;
	port_u8 saved_a;
	port_u8 saved_f;
	struct flag_action_state flag;
	port_u16 flag_address;

	state->a = 1;
	memory[W_IS_KEY_ITEM] = 1;
	state->a = memory[W_CUR_ITEM];
	state->f = comparison_flags(state->a, HM01);
	if ((state->f & PORT_FLAG_C) == 0)
		goto check_if_item_is_hm;

	saved_a = state->a;
	saved_f = state->f;
	state->h = (port_u8)(KEY_ITEM_FLAGS >> 8);
	state->l = (port_u8)KEY_ITEM_FLAGS;
	state->d = (port_u8)(W_BUFFER >> 8);
	state->e = (port_u8)W_BUFFER;
	state->b = 0;
	state->c = 15;
	port_copy_data(state, memory);
	state->a = saved_a;
	state->f = saved_f;
	item = state->a;
	state->a--;
	state->f = (port_u8)(saved_f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((item & 0x0f) == 0)
		state->f |= PORT_FLAG_H;
	state->c = state->a;
	state->h = (port_u8)(W_BUFFER >> 8);
	state->l = (port_u8)W_BUFFER;
	state->b = FLAG_TEST;
	flag.registers = *state;
	flag_address = (port_u16)(W_BUFFER + (state->c >> 3));
	flag.value = memory[flag_address];
	port_flag_action(&flag);
	*state = flag.registers;
	state->a = state->c;
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if (state->a != 0)
		return;


check_if_item_is_hm:
	state->a = memory[W_CUR_ITEM];
	call_is_item_hm(state);
	if ((state->f & PORT_FLAG_C) != 0)
		return;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_IS_KEY_ITEM] = 0;
}
