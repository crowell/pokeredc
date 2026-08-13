#include "port_state.h"

static port_u16
bg_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

__attribute__((noinline, used)) port_u8
port_vblank_copy_bg_map_setup(struct vblank_copy_bg_state *state)
{
	state->registers.a = state->source_low;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0)
		return 0;
	state->registers.h = state->sp_high;
	state->registers.l = state->sp_low;
	state->registers.a = state->registers.h;
	state->temp_high = state->registers.a;
	state->registers.a = state->registers.l;
	state->temp_low = state->registers.a;
	state->registers.a = state->source_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->source_high;
	state->registers.h = state->registers.a;
	state->sp_high = state->registers.h;
	state->sp_low = state->registers.l;
	state->registers.a = state->dest_low;
	state->registers.l = state->registers.a;
	state->registers.a = state->dest_high;
	state->registers.h = state->registers.a;
	state->registers.a = state->num_rows;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->source_low = state->registers.a;
	return 1;
}

/* Returns 1 for another row or 0 after restoring the caller's stack pointer. */
__attribute__((noinline, used)) port_u8
port_transfer_bg_rows_step(struct vblank_copy_bg_state *state)
{
	port_u16 sp = bg_pair(state->sp_high, state->sp_low);
	port_u8 low = state->registers.l;
	port_u8 high = state->registers.h;
	port_u8 old_b;
	port_u8 carry;
	port_u8 i;

	for (i = 0; i < 20; i += 2) {
		state->registers.e = state->source_bytes[i];
		state->registers.d = state->source_bytes[i + 1];
		sp += 2;
		state->written[i] = state->registers.e;
		state->write_h[i] = high;
		state->write_l[i] = low;
		low++;
		state->written[i + 1] = state->registers.d;
		state->write_h[i + 1] = high;
		state->write_l[i + 1] = low;
		if (i != 18)
			low++;
	}
	state->sp_high = (port_u8)(sp >> 8);
	state->sp_low = (port_u8)sp;
	state->registers.a = 13;
	{
		port_u8 left = state->registers.a;
		unsigned int wide = (unsigned int)left + low;
		state->registers.a = (port_u8)wide;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((left & 0x0f) + (low & 0x0f) > 0x0f)
			state->registers.f |= PORT_FLAG_H;
		if (wide > 0xff)
			state->registers.f |= PORT_FLAG_C;
	}
	state->registers.l = state->registers.a;
	carry = state->registers.f & PORT_FLAG_C;
	if (carry)
		high++;
	state->registers.h = high;
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f = carry | PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.b != 0)
		return 1;
	state->registers.a = state->temp_high;
	state->registers.h = state->registers.a;
	state->registers.a = state->temp_low;
	state->registers.l = state->registers.a;
	state->sp_high = state->registers.h;
	state->sp_low = state->registers.l;
	return 0;
}

/* Port of VBlankCopyBgMap and its shared TransferBgRows tail. */
__attribute__((noinline, used)) void
port_vblank_copy_bg_map(struct vblank_copy_bg_state *state, port_u8 *memory)
{
	port_u8 continuation = port_vblank_copy_bg_map_setup(state);
	port_u16 source;
	port_u16 address;
	port_u8 i;

	while (continuation != 0) {
		source = bg_pair(state->sp_high, state->sp_low);
		for (i = 0; i < 20; i++)
			state->source_bytes[i] = memory[(port_u16)(source + i)];
		continuation = port_transfer_bg_rows_step(state);
		for (i = 0; i < 20; i++) {
			address = bg_pair(state->write_h[i], state->write_l[i]);
			memory[address] = state->written[i];
		}
	}
}
