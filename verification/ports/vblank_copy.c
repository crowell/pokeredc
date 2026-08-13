#include "port_state.h"

static port_u16
copy_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

__attribute__((noinline, used)) port_u8
port_vblank_copy_setup(struct vblank_copy_state *state)
{
	state->registers.a = state->size;
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
	state->registers.a = state->size;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->size = state->registers.a;
	return 1;
}

/* Returns 1 for another tile or 0 after saving pointers and restoring SP. */
__attribute__((noinline, used)) port_u8
port_vblank_copy_step(struct vblank_copy_state *state)
{
	port_u16 sp = copy_pair(state->sp_high, state->sp_low);
	port_u16 hl;
	port_u8 low = state->registers.l;
	port_u8 high = state->registers.h;
	port_u8 carry = state->registers.f & PORT_FLAG_C;
	port_u8 old_b;
	port_u8 pair;

	for (pair = 0; pair < 8; pair++) {
		state->registers.e = state->source_bytes[pair * 2];
		state->registers.d = state->source_bytes[pair * 2 + 1];
		sp += 2;
		state->written[pair * 2] = state->registers.e;
		state->write_h[pair * 2] = high;
		state->write_l[pair * 2] = low;
		low++;
		state->written[pair * 2 + 1] = state->registers.d;
		state->write_h[pair * 2 + 1] = high;
		state->write_l[pair * 2 + 1] = low;
		if (pair != 7)
			low++;
	}
	hl = (port_u16)(copy_pair(high, low) + 1);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->sp_high = (port_u8)(sp >> 8);
	state->sp_low = (port_u8)sp;
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f = carry | PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.b != 0)
		return 1;
	state->registers.a = state->registers.l;
	state->dest_low = state->registers.a;
	state->registers.a = state->registers.h;
	state->dest_high = state->registers.a;
	state->registers.h = state->sp_high;
	state->registers.l = state->sp_low;
	state->registers.a = state->registers.l;
	state->source_low = state->registers.a;
	state->registers.a = state->registers.h;
	state->source_high = state->registers.a;
	state->registers.a = state->temp_high;
	state->registers.h = state->registers.a;
	state->registers.a = state->temp_low;
	state->registers.l = state->registers.a;
	state->sp_high = state->registers.h;
	state->sp_low = state->registers.l;
	return 0;
}

/* Port of VBlankCopy in home/vcopy.asm. */
__attribute__((noinline, used)) void
port_vblank_copy(struct vblank_copy_state *state, port_u8 *memory)
{
	port_u8 continuation = port_vblank_copy_setup(state);
	port_u16 source;
	port_u16 address;
	port_u8 i;

	while (continuation != 0) {
		source = copy_pair(state->sp_high, state->sp_low);
		for (i = 0; i < 16; i++)
			state->source_bytes[i] = memory[(port_u16)(source + i)];
		continuation = port_vblank_copy_step(state);
		for (i = 0; i < 16; i++) {
			address = copy_pair(state->write_h[i], state->write_l[i]);
			memory[address] = state->written[i];
		}
	}
}
