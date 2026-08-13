#include "port_state.h"

__attribute__((noinline, used)) void
port_init_cgb_palettes_begin(struct init_cgb_palettes_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->registers.a = 0x80;
	state->background_palette_index = state->registers.a;
	hl++;
	state->registers.c = 32;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

__attribute__((noinline, used)) port_u8
port_init_cgb_palettes_step(struct init_cgb_palettes_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 scaled;
	port_u8 carry;
	port_u8 old_c;

	state->registers.a = state->fetched_index;
	hl++;
	hl++;
	scaled = (port_u8)(state->registers.a << 3);
	state->registers.a = scaled;
	state->registers.d = 0x66;
	state->registers.e = 0x60;
	carry = (port_u8)((unsigned)scaled + 0x60 > 0xff);
	state->registers.a = (port_u8)(scaled + 0x60);
	if (carry)
		state->registers.d++;
	state->registers.a = state->fetched_palette;
	state->background_palette_data = state->registers.a;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (carry)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return state->registers.c == 0;
}

/* Port of InitCGBPalettes in engine/gfx/palettes.asm. */
__attribute__((noinline, used)) void
port_init_cgb_palettes(struct init_cgb_palettes_state *state,
	const port_u8 *source, const port_u8 *palettes)
{
	port_u16 hl;
	port_u16 de;
	port_init_cgb_palettes_begin(state);
	do {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched_index = source[hl];
		de = (port_u16)(0x6660 +
			((port_u8)(state->fetched_index << 3) >= 0xa0 ?
			0x100 : 0));
		state->fetched_palette = palettes[de];
		port_init_cgb_palettes_step(state);
	} while (state->registers.c != 0);
}
