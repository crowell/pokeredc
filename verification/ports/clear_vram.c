#include "port_state.h"

/* Port of ClearVram in home/init.asm.
 *
 * Clears all of VRAM (0x8000-0x9FFF) by calling FillMemory with the VRAM
 * address range and a fill byte of 0. */

#define VRAM_START 0x8000u
#define VRAM_SIZE 0x2000u

/* Forward declaration of the FillMemory port. */
__attribute__((noinline, used)) void
port_fill_memory(struct fill_memory_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_clear_vram(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	struct fill_memory_state fill_state = {0};

	/* Set up registers as ClearVram does: HL = VRAM_START, BC = VRAM_SIZE, A = 0 */
	fill_state.registers.h = (port_u8)(VRAM_START >> 8);
	fill_state.registers.l = (port_u8)VRAM_START;
	fill_state.registers.b = (port_u8)(VRAM_SIZE >> 8);
	fill_state.registers.c = (port_u8)VRAM_SIZE;
	fill_state.registers.a = 0;

	port_fill_memory(&fill_state, memory);
}