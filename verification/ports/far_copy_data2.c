#include "port_state.h"

/* Port of FarCopyData2 in home/copy2.asm.
 *
 * Identical to FarCopyData except it stashes the source ROM bank in
 * hROMBankTemp instead of wBuffer. Switches the ROM bank to A, copies BC bytes
 * from [HL] to [DE] via CopyData, then restores the bank. The bank switch is a
 * no-op for the observable in the flat memory model, so the native port just
 * copies BC bytes from [HL] to [DE]. */

__attribute__((noinline, used)) void
port_far_copy_data2(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = ((port_u16)state->h << 8) | (port_u16)state->l;
	port_u16 de = ((port_u16)state->d << 8) | (port_u16)state->e;
	port_u16 bc = ((port_u16)state->b << 8) | (port_u16)state->c;
	for (port_u16 i = 0; i < bc; i++) {
		memory[de + i] = memory[hl + i];
	}
}
