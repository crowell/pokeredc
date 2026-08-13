#include "port_state.h"

/* Port of LoadCoinsToSubtract in engine/events/prize_menu.asm. */
__attribute__((noinline, used)) void
port_load_coins_to_subtract(struct coin_load_state *state)
{
	port_u16 hl;

	state->registers.a = state->which_prize;
	state->registers.a = (port_u8)(state->registers.a << 1);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	hl = (port_u16)(0xd141 + state->registers.e);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->unused_coins_byte = state->registers.a;
	state->registers.a = state->fetched_high;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->coins_high = state->registers.a;
	state->registers.a = state->fetched_low;
	state->coins_low = state->registers.a;
}

/* Port of LoadVendingMachineItem in engine/events/vending_machine.asm. */
__attribute__((noinline, used)) void
port_load_vending_machine_item(struct vending_load_state *state)
{
	port_u8 doubled;
	port_u16 hl;
	unsigned int index;

	state->registers.h = 0x50;
	state->registers.l = 0x00;
	state->registers.a = state->current_menu_item;
	doubled = (port_u8)(state->registers.a << 1);
	state->registers.a = (port_u8)(doubled << 1);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	hl = (port_u16)(0x5000 + state->registers.e);
	/* ADD HL,DE preserves only the Z result from the second ADD A here. */
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	for (index = 0; index < 4; index++) {
		state->registers.a = state->fetched[index];
		if (index == 0)
			state->item = state->registers.a;
		else
			state->price[index - 1] = state->registers.a;
		if (index != 3) {
			hl++;
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
		}
	}
}

__attribute__((noinline, used)) void
port_get_prize_mon_level_begin(struct prize_level_state *state)
{
	state->registers.a = state->species;
	state->registers.b = state->registers.a;
	state->registers.h = 0x69;
	state->registers.l = 0x8a;
}

__attribute__((noinline, used)) port_u8
port_get_prize_mon_level_step(struct prize_level_state *state)
{
	port_u8 left;
	port_u8 right;
	port_u16 hl;

	state->registers.a = state->fetched_species;
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	left = state->registers.a;
	right = state->registers.b;
	state->registers.f = PORT_FLAG_N;
	if (left == right)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (left < right)
		state->registers.f |= PORT_FLAG_C;
	if (left == right)
		return 1;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
}

__attribute__((noinline, used)) void
port_get_prize_mon_level_finish(struct prize_level_state *state)
{
	state->registers.a = state->fetched_level;
	state->enemy_level = state->registers.a;
}

/* Port of GetPrizeMonLevel in engine/events/prize_menu.asm. */
__attribute__((noinline, used)) void
port_get_prize_mon_level(struct prize_level_state *state, const port_u8 *dictionary)
{
	port_u16 offset = 0;

	port_get_prize_mon_level_begin(state);
	for (;;) {
		state->fetched_species = dictionary[offset];
		if (port_get_prize_mon_level_step(state))
			break;
		offset += 2;
	}
	state->fetched_level = dictionary[offset + 1];
	port_get_prize_mon_level_finish(state);
}
