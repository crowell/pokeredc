#include "port_state.h"

/*
 * Port of FarCopyData3 in home/copy2.asm.
 *
 * Like FarCopyData, but copies bc bytes from a:de to hl (the reverse
 * direction) and uses hROMBankTemp as scratch instead of wBuffer. The ROM bank
 * switch is a no-op in the flat memory model, so the native port simply copies
 * bc bytes from [DE] to [HL].
 */

__attribute__((noinline, used)) void
port_far_copy_data3(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = ((port_u16)state->h << 8) | (port_u16)state->l;
	port_u16 de = ((port_u16)state->d << 8) | (port_u16)state->e;
	port_u16 bc = ((port_u16)state->b << 8) | (port_u16)state->c;
	port_u16 i;
	for (i = 0; i < bc; i++) {
		memory[hl + i] = memory[de + i];
	}
}
