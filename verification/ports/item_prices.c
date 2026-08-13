#include "port_state.h"

/* Port of GetMachinePrice in engine/items/tm_prices.asm. */
__attribute__((noinline, used)) void
port_get_machine_price(struct machine_price_state *state)
{
	port_u8 item;
	port_u8 offset;
	port_u8 result;
	port_u16 hl;

	state->registers.a = state->current_item;
	item = state->registers.a;
	result = (port_u8)(item - 0xc9);
	state->registers.a = result;
	state->registers.f = PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((item & 0x0f) < 9)
		state->registers.f |= PORT_FLAG_H;
	if (item < 0xc9) {
		state->registers.f |= PORT_FLAG_C;
		return;
	}
	offset = result;
	state->registers.d = offset;
	state->registers.a = (port_u8)(offset >> 1);
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	hl = (port_u16)(0x7fa7 + state->registers.c);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->fetched;
	state->registers.d >>= 1;
	if ((offset & 1) != 0)
		state->registers.a = (port_u8)((state->registers.a << 4) |
			(state->registers.a >> 4));
	state->registers.a &= 0xf0;
	state->item_price[1] = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->item_price[0] = state->registers.a;
	state->item_price[2] = state->registers.a;
}
