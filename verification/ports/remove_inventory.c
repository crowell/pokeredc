#include "port_state.h"

static port_u16
remove_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static port_u16
remove_target(port_u16 original, port_u8 which)
{
	port_u16 pointer = (port_u16)(original + 1);
	port_u8 offset = (port_u8)(which << 1);
	port_u16 low_sum = (port_u16)(port_u8)pointer + offset;

	pointer = (port_u16)((pointer & 0xff00) | (port_u8)low_sum);
	if (low_sum > 0xff)
		pointer = (port_u16)(pointer + 0x100);
	return (port_u16)(pointer + 1);
}

/* Returns 1 at the compaction loop or 0 after the nonempty-slot return. */
__attribute__((noinline, used)) port_u8
port_remove_item_from_inventory_begin(struct remove_inventory_state *state)
{
	port_u16 original = remove_pair(state->registers.h, state->registers.l);
	port_u16 target = remove_target(original, state->which_item);
	port_u8 left = state->current_quantity;
	port_u8 right = state->item_quantity;
	port_u8 result = (port_u8)(left - right);
	port_u16 pointer;

	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.e = state->item_quantity;
	state->registers.a = result;
	state->registers.f = PORT_FLAG_N;
	if (result == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		state->registers.f |= PORT_FLAG_H;
	if (left < right)
		state->registers.f |= PORT_FLAG_C;
	state->written = state->registers.a;
	state->max_item_quantity = state->registers.a;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0) {
		state->registers.h = state->saved_h;
		state->registers.l = state->saved_l;
		return 0;
	}
	pointer = (port_u16)(target - 1);
	state->registers.h = (port_u8)(pointer >> 8);
	state->registers.l = (port_u8)pointer;
	pointer = (port_u16)(pointer + 2);
	state->registers.d = (port_u8)(pointer >> 8);
	state->registers.e = (port_u8)pointer;
	return 1;
}

/* Returns 1 for another compaction byte or 0 for the postlude. */
__attribute__((noinline, used)) port_u8
port_remove_item_from_inventory_step(struct remove_inventory_state *state)
{
	port_u16 de = remove_pair(state->registers.d, state->registers.e);
	port_u16 hl = remove_pair(state->registers.h, state->registers.l);
	port_u8 value = state->fetched_next;

	state->registers.a = value;
	de++;
	state->written = state->registers.a;
	hl++;
	state->registers.f = PORT_FLAG_N;
	if (value == 0xff)
		state->registers.f |= PORT_FLAG_Z;
	if ((value & 0x0f) < 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (value < 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return value != 0xff;
}

__attribute__((noinline, used)) void
port_remove_item_from_inventory_finish(struct remove_inventory_state *state)
{
	port_u8 old;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->list_scroll_offset = 0;
	state->current_menu_item = 0;
	state->bag_saved_menu_item = 0;
	state->saved_list_scroll_offset = 0;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.a = state->inventory_count;
	old = state->registers.a;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	state->inventory_count = state->registers.a;
	state->list_count = state->registers.a;
	{
		port_u8 value = state->registers.a;
		state->registers.f = PORT_FLAG_N;
		if (value == 2)
			state->registers.f |= PORT_FLAG_Z;
		if ((value & 0x0f) < 2)
			state->registers.f |= PORT_FLAG_H;
		if (value < 2)
			state->registers.f |= PORT_FLAG_C;
	}
	if (state->registers.a >= 2)
		state->max_menu_item = state->registers.a;
}

/* Port of RemoveItemFromInventory_ in engine/items/inventory.asm. */
__attribute__((noinline, used)) void
port_remove_item_from_inventory(struct remove_inventory_state *state,
	port_u8 *memory)
{
	port_u16 original = remove_pair(state->registers.h, state->registers.l);
	port_u16 target = remove_target(original, state->which_item);
	port_u16 source;
	port_u16 destination;

	state->current_quantity = memory[target];
	if (!port_remove_item_from_inventory_begin(state)) {
		memory[target] = state->written;
		return;
	}
	memory[target] = state->written;
	do {
		source = remove_pair(state->registers.d, state->registers.e);
		destination = remove_pair(state->registers.h, state->registers.l);
		state->fetched_next = memory[source];
		port_remove_item_from_inventory_step(state);
		memory[destination] = state->written;
	} while (state->registers.a != 0xff);
	state->inventory_count = memory[original];
	port_remove_item_from_inventory_finish(state);
	memory[original] = state->inventory_count;
}
