#include "port_state.h"

port_u8 port_transfer_bg_rows_step(struct vblank_copy_bg_state *state);

static port_u16
auto_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
auto_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = auto_pair(registers->h, registers->l);
	unsigned int wide = (unsigned int)left + right;

	registers->h = (port_u8)(wide >> 8);
	registers->l = (port_u8)wide;
	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xffff)
		registers->f |= PORT_FLAG_C;
}

/* Returns 1 to enter TransferBgRows or 0 for the disabled return. */
__attribute__((noinline, used)) port_u8
port_auto_bg_map_transfer_setup(struct auto_bg_transfer_state *state)
{
	port_u8 initial_portion;

	state->registers.a = state->enabled;
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
	state->registers.a = state->portion;
	initial_portion = state->registers.a;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (initial_portion == 0) {
		state->registers.h = 0xc3;
		state->registers.l = 0xa0;
		state->sp_high = state->registers.h;
		state->sp_low = state->registers.l;
		state->registers.a = state->dest_high;
		state->registers.h = state->registers.a;
		state->registers.a = state->dest_low;
		state->registers.l = state->registers.a;
		state->registers.a = 1;
	} else if (initial_portion == 1) {
		state->registers.a--;
		state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
		state->registers.h = 0xc4;
		state->registers.l = 0x18;
		state->sp_high = state->registers.h;
		state->sp_low = state->registers.l;
		state->registers.a = state->dest_high;
		state->registers.h = state->registers.a;
		state->registers.a = state->dest_low;
		state->registers.l = state->registers.a;
		state->registers.d = 0;
		state->registers.e = 0xc0;
		auto_add_hl(&state->registers, 0x00c0);
		state->registers.a = 2;
	} else {
		port_u8 old = state->registers.a;

		state->registers.a--;
		state->registers.f = PORT_FLAG_N;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
		state->registers.h = 0xc4;
		state->registers.l = 0x90;
		state->sp_high = state->registers.h;
		state->sp_low = state->registers.l;
		state->registers.a = state->dest_high;
		state->registers.h = state->registers.a;
		state->registers.a = state->dest_low;
		state->registers.l = state->registers.a;
		state->registers.d = 1;
		state->registers.e = 0x80;
		auto_add_hl(&state->registers, 0x0180);
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
	state->portion = state->registers.a;
	state->registers.b = 6;
	return 1;
}

__attribute__((noinline, used)) port_u8
port_auto_bg_map_transfer_row_step(struct auto_bg_transfer_state *state)
{
	struct vblank_copy_bg_state row;
	port_u8 continuation;
	port_u8 i;

	row.registers = state->registers;
	row.sp_high = state->sp_high;
	row.sp_low = state->sp_low;
	row.temp_high = state->temp_high;
	row.temp_low = state->temp_low;
	for (i = 0; i < 20; i++)
		row.source_bytes[i] = state->source_bytes[i];
	continuation = port_transfer_bg_rows_step(&row);
	state->registers = row.registers;
	state->sp_high = row.sp_high;
	state->sp_low = row.sp_low;
	for (i = 0; i < 20; i++) {
		state->written[i] = row.written[i];
		state->write_h[i] = row.write_h[i];
		state->write_l[i] = row.write_l[i];
	}
	return continuation;
}

/* Port of AutoBgMapTransfer in home/vcopy.asm. */
__attribute__((noinline, used)) void
port_auto_bg_map_transfer(struct auto_bg_transfer_state *state,
	port_u8 *memory)
{
	port_u8 continuation = port_auto_bg_map_transfer_setup(state);
	port_u16 source;
	port_u16 address;
	port_u8 i;

	while (continuation != 0) {
		source = auto_pair(state->sp_high, state->sp_low);
		for (i = 0; i < 20; i++)
			state->source_bytes[i] = memory[(port_u16)(source + i)];
		continuation = port_auto_bg_map_transfer_row_step(state);
		for (i = 0; i < 20; i++) {
			address = auto_pair(state->write_h[i], state->write_l[i]);
			memory[address] = state->written[i];
		}
	}
}
