#include "port_state.h"

enum add_inventory_continuation {
	ADD_INVENTORY_RETURN = 0,
	ADD_INVENTORY_SCAN = 1,
	ADD_INVENTORY_NEW = 2,
	ADD_INVENTORY_QUANTITY = 3,
};

static port_u16
add_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
add_inventory_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
add_inventory_unwind(struct add_inventory_state *state)
{
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.b = state->saved_a;
	state->registers.c = state->saved_f;
	state->registers.a = state->registers.b;
	state->item_quantity = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_add_item_to_inventory_setup(struct add_inventory_state *state)
{
	port_u16 original = add_pair(state->registers.h, state->registers.l);
	port_u8 count = state->inventory_count;
	port_u8 capacity = original == 0xd31d ? 20 : 50;

	state->saved_a = state->item_quantity;
	state->saved_f = state->registers.f;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.d = (port_u8)(count - capacity);
	state->registers.a = count;
	original++;
	state->registers.h = (port_u8)(original >> 8);
	state->registers.l = (port_u8)original;
	state->registers.f = PORT_FLAG_H;
	if (count == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.h = state->saved_h;
		state->registers.l = state->saved_l;
		return ADD_INVENTORY_NEW;
	}
	return ADD_INVENTORY_SCAN;
}

__attribute__((noinline, used)) port_u8
port_add_item_to_inventory_scan(struct add_inventory_state *state)
{
	port_u16 hl = add_pair(state->registers.h, state->registers.l);

	state->registers.a = state->fetched_item;
	hl++;
	state->registers.b = state->registers.a;
	state->registers.a = state->cur_item;
	add_inventory_cp(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b) {
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return ADD_INVENTORY_QUANTITY;
	}
	hl++;
	state->registers.a = state->fetched_marker;
	add_inventory_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff) {
		state->registers.h = state->saved_h;
		state->registers.l = state->saved_l;
		return ADD_INVENTORY_NEW;
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return ADD_INVENTORY_SCAN;
}

__attribute__((noinline, used)) port_u8
port_add_item_to_inventory_quantity(struct add_inventory_state *state)
{
	port_u16 hl = add_pair(state->registers.h, state->registers.l);
	port_u8 left;
	port_u8 right;
	port_u16 wide;

	state->quantity_write_valid = 0;
	state->registers.a = state->item_quantity;
	state->registers.b = state->registers.a;
	state->registers.a = state->existing_quantity;
	left = state->registers.a;
	right = state->registers.b;
	wide = (port_u16)left + right;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	add_inventory_cp(&state->registers, 100);
	if (state->registers.a < 100) {
		state->quantity_written = state->registers.a;
		state->quantity_write_valid = 1;
		state->registers.f =
			(state->registers.f & PORT_FLAG_Z) | PORT_FLAG_C;
		add_inventory_unwind(state);
		return ADD_INVENTORY_RETURN;
	}
	left = state->registers.a;
	state->registers.a = (port_u8)(left - 99);
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < 3)
		state->registers.f |= PORT_FLAG_H;
	if (left < 99)
		state->registers.f |= PORT_FLAG_C;
	state->item_quantity = state->registers.a;
	state->registers.a = state->registers.d;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.h = state->saved_h;
		state->registers.l = state->saved_l;
		add_inventory_unwind(state);
		return ADD_INVENTORY_RETURN;
	}
	state->registers.a = 99;
	state->quantity_written = state->registers.a;
	state->quantity_write_valid = 1;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return ADD_INVENTORY_SCAN;
}

__attribute__((noinline, used)) void
port_add_item_to_inventory_new(struct add_inventory_state *state)
{
	port_u16 hl = add_pair(state->registers.h, state->registers.l);
	port_u8 new_count;
	port_u8 offset;

	state->add_write_valid = 0;
	state->registers.a = state->registers.d;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		add_inventory_unwind(state);
		return;
	}
	new_count = (port_u8)(state->inventory_count + 1);
	state->inventory_count = new_count;
	state->count_written = new_count;
	state->registers.a = new_count;
	offset = (port_u8)(state->registers.a + state->registers.a);
	offset--;
	state->registers.c = offset;
	state->registers.b = 0;
	hl = (port_u16)(hl + offset);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->cur_item;
	state->item_written = state->registers.a;
	hl++;
	state->registers.a = state->item_quantity;
	state->quantity_written = state->registers.a;
	hl++;
	state->terminator_written = 0xff;
	state->add_write_valid = 1;
	state->registers.f = PORT_FLAG_C;
	add_inventory_unwind(state);
}

/* Port of AddItemToInventory_ in engine/items/inventory.asm. */
__attribute__((noinline, used)) void
port_add_item_to_inventory(struct add_inventory_state *state, port_u8 *memory)
{
	port_u16 original = add_pair(state->registers.h, state->registers.l);
	port_u16 pointer;
	port_u8 continuation;

	state->inventory_count = memory[original];
	continuation = port_add_item_to_inventory_setup(state);
	for (;;) {
		if (continuation == ADD_INVENTORY_SCAN) {
			pointer = add_pair(state->registers.h, state->registers.l);
			state->fetched_item = memory[pointer];
			state->fetched_marker = memory[(port_u16)(pointer + 2)];
			continuation = port_add_item_to_inventory_scan(state);
		} else if (continuation == ADD_INVENTORY_QUANTITY) {
			pointer = add_pair(state->registers.h, state->registers.l);
			state->existing_quantity = memory[pointer];
			continuation = port_add_item_to_inventory_quantity(state);
			if (state->quantity_write_valid)
				memory[pointer] = state->quantity_written;
		} else {
			port_add_item_to_inventory_new(state);
			if (state->add_write_valid) {
				port_u8 count = state->inventory_count;
				pointer = (port_u16)(original + (port_u8)(count + count - 1));
				memory[original] = state->count_written;
				memory[pointer] = state->item_written;
				memory[(port_u16)(pointer + 1)] = state->quantity_written;
				memory[(port_u16)(pointer + 2)] = state->terminator_written;
			}
			return;
		}
		if (continuation == ADD_INVENTORY_RETURN)
			return;
	}
}
