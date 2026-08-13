#include "port_state.h"

static const port_u8 dma_code[10] = {
	0x3e, 0xc3, 0xe0, 0x46, 0x3e, 0x28, 0x3d, 0x20, 0xfd, 0xc9,
};

static void
dec_register(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 result = (port_u8)(old - 1);
	port_u8 next_flags = (*flags & PORT_FLAG_C) | PORT_FLAG_N;

	if (result == 0)
		next_flags |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		next_flags |= PORT_FLAG_H;
	*value = result;
	*flags = next_flags;
}

/* Port of WriteDMACodeToHRAM in engine/gfx/oam_dma.asm. */
__attribute__((noinline, used)) void
port_write_dma_code_to_hram(struct dma_code_copy_state *state)
{
	port_u16 source = 0x4bfb;
	port_u8 index = 0;

	state->registers.c = 0x80;
	state->registers.b = 10;
	state->registers.h = (port_u8)(source >> 8);
	state->registers.l = (port_u8)source;
	do {
		state->registers.a = dma_code[index];
		index++;
		source++;
		state->hram[state->registers.c - 0x80] = state->registers.a;
		state->registers.c++;
		dec_register(&state->registers.b, &state->registers.f);
	} while (state->registers.b != 0);
	state->registers.h = (port_u8)(source >> 8);
	state->registers.l = (port_u8)source;
}

/* Port of hDMARoutine in engine/gfx/oam_dma.asm. */
__attribute__((noinline, used)) void
port_hdma_routine(struct dma_routine_state *state)
{
	state->registers.a = 0xc3;
	state->dma_register = state->registers.a;
	state->registers.a = 0x28;
	do {
		dec_register(&state->registers.a, &state->registers.f);
	} while (state->registers.a != 0);
}
