#include "port_state.h"

#define CLA_ATTACK_DOWN_SIDE_EFFECT 0x44u
#define CLA_NOTHING_HAPPENED_TEXT 0x7b3eu

void port_print_text(struct cpu_register_state *state, port_u8 *memory);

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

/* Port of CantLowerAnymore in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_cant_lower_anymore(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 de = (port_u16)(((port_u16)registers->d << 8) | registers->e);

	registers->a = memory[de];
	set_cp_flags(registers, CLA_ATTACK_DOWN_SIDE_EFFECT);
	if (!(registers->f & PORT_FLAG_C))
		return;
	registers->h = (port_u8)(CLA_NOTHING_HAPPENED_TEXT >> 8);
	registers->l = (port_u8)CLA_NOTHING_HAPPENED_TEXT;
	port_print_text(registers, memory);
}
