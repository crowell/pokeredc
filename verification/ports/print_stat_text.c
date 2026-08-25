#include "port_state.h"

#define PST_STAT_MOD_TEXT_STRINGS 0x769fu
#define PST_STRING_BUFFER 0xcf4bu
#define PST_TERMINATOR 0x50u
#define PST_STAT_NAME_LENGTH 10u

void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

static void
decrement_b(struct cpu_register_state *registers)
{
	port_u8 old = registers->b;
	registers->b--;
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_N);
	if (registers->b == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
compare_a_c(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->c;
	port_u8 result = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

/* Port of PrintStatText in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_print_stat_text(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 hl = PST_STAT_MOD_TEXT_STRINGS;

	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->c = PST_TERMINATOR;
	for (;;) {
		decrement_b(registers);
		if (registers->f & PORT_FLAG_Z)
			break;
		do {
			registers->a = memory[hl++];
			registers->h = (port_u8)(hl >> 8);
			registers->l = (port_u8)hl;
			compare_a_c(registers);
		} while (!(registers->f & PORT_FLAG_Z));
	}
	registers->d = (port_u8)(PST_STRING_BUFFER >> 8);
	registers->e = (port_u8)PST_STRING_BUFFER;
	registers->b = 0;
	registers->c = PST_STAT_NAME_LENGTH;
	port_copy_data(registers, memory);
}
