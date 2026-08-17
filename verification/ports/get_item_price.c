#include "port_state.h"

#define W_CUR_ITEM                  0xcf91
#define W_ITEM_PRICES               0xcf8f
#define H_ITEM_PRICE                0xff8b
#define HM01                        0xc4
#define TM01                        0xc9
#define TECHNICAL_MACHINE_PRICES    0x7fa7

/* Port of GetItemPrice in home/item_price.asm.
 *
 * Reads [wCurItem]. For a regular item (id < HM01) it indexes the item price
 * table whose 16-bit base is held by the pointer at wItemPrices, copying the
 * 3-byte packed-BCD price into hItemPrice. For a TM/HM item (id >= HM01) it
 * delegates to GetMachinePrice (the proven port_get_machine_price), which
 * stores the price into hItemPrice for TMs and leaves it untouched for HMs
 * (priceless). ROM-bank switching is irrelevant under the flat-memory model. */

void port_get_machine_price(struct machine_price_state *state);

struct get_item_price_state {
	port_u8 f; /* carry observable: set (PORT_FLAG_C) when an HM is priceless */
};

__attribute__((noinline, used)) void
port_get_item_price(struct get_item_price_state *state, port_u8 *memory)
{
	port_u8 item = memory[W_CUR_ITEM];

	if (item >= HM01) {
		struct machine_price_state ms;
		port_u8 offset = (port_u8)(item - TM01);
		port_u16 tbl = (port_u16)(TECHNICAL_MACHINE_PRICES + (offset >> 1));

		ms.current_item = item;
		ms.fetched = memory[tbl];
		ms.item_price[0] = 0;
		ms.item_price[1] = 0;
		ms.item_price[2] = 0;
		ms.registers.a = 0;
		ms.registers.f = 0;
		ms.registers.b = 0;
		ms.registers.c = 0;
		ms.registers.d = 0;
		ms.registers.e = 0;
		ms.registers.h = 0;
		ms.registers.l = 0;

		port_get_machine_price(&ms);
		if ((ms.registers.f & PORT_FLAG_C) == 0) {
			/* TM: price written to hItemPrice. */
			memory[H_ITEM_PRICE] = ms.item_price[0];
			memory[H_ITEM_PRICE + 1] = ms.item_price[1];
			memory[H_ITEM_PRICE + 2] = ms.item_price[2];
			state->f = 0;
		} else {
			/* HM: priceless, hItemPrice left unchanged. */
			state->f = PORT_FLAG_C;
		}
		return;
	}

	{
		port_u16 ptr = (port_u16)(memory[W_ITEM_PRICES] |
			((port_u16)memory[W_ITEM_PRICES + 1] << 8));
		port_u8 index = (port_u8)(item - 1);
		port_u16 src = (port_u16)(ptr + (port_u16)(3 * index));

		memory[H_ITEM_PRICE] = memory[src];
		memory[H_ITEM_PRICE + 1] = memory[src + 1];
		memory[H_ITEM_PRICE + 2] = memory[src + 2];
		state->f = 0;
	}
}
