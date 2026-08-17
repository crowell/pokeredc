#include "port_state.h"

#define W_CUR_ITEM             0xcf91
#define W_ACTION_RESULT        0xcd6a
#define HM01                   0xc4
#define ITEM_USE_PTR_TABLE     0x55e1
#define ITEM_USE_TMHM          0x6479

/* Port of UseItem_ in engine/items/item_effects.asm (the real routine reached
 * through the `farjp UseItem_` wrapper in home/item.asm).
 *
 * Initialises wActionResultOrTookBattleTurn to 1 (success), then dispatches to
 * the item's handler. For a TM/HM item it jumps to ItemUseTMHM; otherwise it
 * loads the handler address from the ItemUsePtrTable, indexed by
 * (wCurItem - 1) * 2. The final indirect `jp hl` is a compositional boundary;
 * the resolved handler address is reported in dispatched_hl for the caller to
 * continue execution. */

struct use_item_state {
	port_u16 dispatched_hl; /* handler address to jump to (boundary) */
};

__attribute__((noinline, used)) void
port_use_item_(struct use_item_state *state, port_u8 *memory)
{
	port_u8 item = memory[W_CUR_ITEM];
	port_u16 target;

	memory[W_ACTION_RESULT] = 1;

	if (item >= HM01) {
		target = ITEM_USE_TMHM;
	} else {
		port_u8 index = (port_u8)(item - 1);
		port_u16 off = (port_u16)(2 * index);
		port_u16 addr = (port_u16)(ITEM_USE_PTR_TABLE + off);

		target = (port_u16)(memory[addr] |
			((port_u16)memory[addr + 1] << 8));
	}

	state->dispatched_hl = target;
}
