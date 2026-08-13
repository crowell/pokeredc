#include "port_state.h"

__attribute__((noinline, used)) void
port_copy_sgb_border_tiles_begin(struct sgb_border_copy_state *state)
{
	state->registers.b = 128;
}

__attribute__((noinline, used)) void
port_copy_sgb_border_tiles_copy_begin(struct sgb_border_copy_state *state)
{
	state->registers.c = 16;
}

static void
dec_register(port_u8 *value, port_u8 *flags)
{
	port_u8 old = *value;
	port_u8 result = (port_u8)(old - 1);
	port_u8 next = (*flags & PORT_FLAG_C) | PORT_FLAG_N;
	if (result == 0)
		next |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		next |= PORT_FLAG_H;
	*value = result;
	*flags = next;
}

__attribute__((noinline, used)) port_u8
port_copy_sgb_border_tiles_copy_step(struct sgb_border_copy_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	state->registers.a = state->fetched;
	hl++;
	state->written = state->registers.a;
	de++;
	dec_register(&state->registers.c, &state->registers.f);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) void
port_copy_sgb_border_tiles_zero_begin(struct sgb_border_copy_state *state)
{
	state->registers.c = 16;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
}

__attribute__((noinline, used)) port_u8
port_copy_sgb_border_tiles_zero_step(struct sgb_border_copy_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	state->written = state->registers.a;
	de++;
	dec_register(&state->registers.c, &state->registers.f);
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_copy_sgb_border_tiles_tile_step(struct sgb_border_copy_state *state)
{
	dec_register(&state->registers.b, &state->registers.f);
	return state->registers.b == 0;
}

/* Port of CopySGBBorderTiles in engine/gfx/palettes.asm. */
__attribute__((noinline, used)) void
port_copy_sgb_border_tiles(struct sgb_border_copy_state *state,
	const port_u8 *source, port_u8 *destination)
{
	port_u16 hl;
	port_u16 de;
	port_copy_sgb_border_tiles_begin(state);
	do {
		port_copy_sgb_border_tiles_copy_begin(state);
		do {
			hl = (port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l);
			de = (port_u16)(((port_u16)state->registers.d << 8) |
				state->registers.e);
			state->fetched = source[hl];
			port_copy_sgb_border_tiles_copy_step(state);
			destination[de] = state->written;
		} while (state->registers.c != 0);
		port_copy_sgb_border_tiles_zero_begin(state);
		do {
			de = (port_u16)(((port_u16)state->registers.d << 8) |
				state->registers.e);
			port_copy_sgb_border_tiles_zero_step(state);
			destination[de] = state->written;
		} while (state->registers.c != 0);
		port_copy_sgb_border_tiles_tile_step(state);
	} while (state->registers.b != 0);
}
