#include "port_state.h"

/* Port of HallOfFame_Copy in engine/menus/save.asm.
 *
 * Enables SRAM, copies BC bytes from [HL] to [DE] (the caller points DE at
 * wHallOfFame and HL at the saved team slot), then disables SRAM. The SRAM
 * enable/disable is a no-op for the observable in the flat memory model. */

__attribute__((noinline, used)) void
port_hall_of_fame_copy(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = ((port_u16)state->h << 8) | (port_u16)state->l;
	port_u16 de = ((port_u16)state->d << 8) | (port_u16)state->e;
	port_u16 bc = ((port_u16)state->b << 8) | (port_u16)state->c;
	for (port_u16 i = 0; i < bc; i++) {
		memory[de + i] = memory[hl + i];
	}
}
