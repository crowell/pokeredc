#include "port_state.h"

#define MM_W_MOVE_DIDNT_MISS 0xccf4u
#define MM_ATTACK_DOWN_SIDE_EFFECT 0x44u

port_u8 port_conditional_print_but_it_failed(
	struct memory_predicate_state *state);
void port_print_but_it_failed_text_(struct cpu_register_state *state,
	port_u8 *memory);

static void
set_cp_flags(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of MoveMissed in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_move_missed(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	struct memory_predicate_state conditional;

	registers->a = memory[de];
	set_cp_flags(registers, MM_ATTACK_DOWN_SIDE_EFFECT);
	if (!(registers->f & PORT_FLAG_C))
		return;
	conditional.registers = *registers;
	conditional.value = memory[MM_W_MOVE_DIDNT_MISS];
	if (port_conditional_print_but_it_failed(&conditional))
		port_print_but_it_failed_text_(&conditional.registers, memory);
	*registers = conditional.registers;
}
