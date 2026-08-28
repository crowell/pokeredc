#include "port_state.h"

#define W_STATUS_FLAGS5 0xd730u
#define W_TEXT_BOX_ID 0xd125u
#define W_CHOSEN_MENU_ITEM 0xd12du
#define W_MENU_EXIT_METHOD 0xd12eu
#define W_TOP_MENU_ITEM_Y 0xcc24u
#define W_TOP_MENU_ITEM_X 0xcc25u
#define W_CURRENT_MENU_ITEM 0xcc26u
#define W_MAX_MENU_ITEM 0xcc28u
#define W_MENU_WATCHED_KEYS 0xcc29u
#define W_LAST_MENU_ITEM 0xcc2au
#define W_MENU_WATCH_MOVING_OUT_OF_BOUNDS 0xcc37u
#define W_MENU_CURSOR_LOCATION 0xcc30u

#define BUY_SELL_QUIT_MENU_TEMPLATE 0x0eu
#define PAD_A 0x01u
#define PAD_B 0x02u
#define CHOSE_MENU_ITEM 0x01u
#define CANCELLED_MENU 0x02u
#define BIT_NO_TEXT_DELAY 6u
#define PORT_FLAG_C 0x10u
#define PORT_FLAG_H 0x20u
#define PORT_FLAG_N 0x40u
#define PORT_FLAG_Z 0x80u

void port_display_text_box_id(struct cpu_register_state *, port_u8 *);
void port_handle_menu_input(struct memory_predicate_state *);
void port_place_unfilled_arrow_menu_cursor(struct menu_cursor_store_state *);

static port_u8
compare_flags(port_u8 left, port_u8 right, port_u8 old_flags)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N | (old_flags & PORT_FLAG_C);
	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of DoBuySellQuitMenu in engine/menus/text_box.asm. */
__attribute__((noinline, used)) void
port_do_buy_sell_quit_menu(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct memory_predicate_state input;
	struct menu_cursor_store_state cursor;
	port_u8 current;
	port_u8 max;
	port_u8 button;

	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << BIT_NO_TEXT_DELAY);
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[W_CHOSEN_MENU_ITEM] = 0;
	memory[W_TEXT_BOX_ID] = BUY_SELL_QUIT_MENU_TEMPLATE;
	port_display_text_box_id(registers, memory);

	memory[W_MENU_WATCHED_KEYS] = PAD_A | PAD_B;
	memory[W_MAX_MENU_ITEM] = 2;
	memory[W_TOP_MENU_ITEM_Y] = 1;
	memory[W_TOP_MENU_ITEM_X] = 1;
	memory[W_CURRENT_MENU_ITEM] = 0;
	memory[W_LAST_MENU_ITEM] = 0;
	memory[W_MENU_WATCH_MOVING_OUT_OF_BOUNDS] = 0;
	memory[W_STATUS_FLAGS5] &= (port_u8)~(1u << BIT_NO_TEXT_DELAY);

	input.registers = *registers;
	port_handle_menu_input(&input);
	*registers = input.registers;
	button = registers->a;

	cursor.registers = *registers;
	cursor.cursor_low = memory[W_MENU_CURSOR_LOCATION];
	cursor.cursor_high = memory[W_MENU_CURSOR_LOCATION + 1];
	port_place_unfilled_arrow_menu_cursor(&cursor);
	*registers = cursor.registers;
	memory[W_MENU_CURSOR_LOCATION] = cursor.cursor_low;
	memory[W_MENU_CURSOR_LOCATION + 1] = cursor.cursor_high;
	memory[(port_u16)(((port_u16)cursor.cursor_high << 8) |
		cursor.cursor_low)] = cursor.destination;

	current = memory[W_CURRENT_MENU_ITEM];
	max = memory[W_MAX_MENU_ITEM];
	if ((button & PAD_A) != 0 || (button & PAD_B) == 0) {
		memory[W_MENU_EXIT_METHOD] = CHOSE_MENU_ITEM;
		memory[W_CHOSEN_MENU_ITEM] = current;
		registers->b = current;
		registers->a = max;
		registers->f = compare_flags(max, current, registers->f);
		if (max != current)
			return;
	}

	memory[W_MENU_EXIT_METHOD] = CANCELLED_MENU;
	memory[W_CHOSEN_MENU_ITEM] = current;
	registers->a = current;
	registers->f = (port_u8)(registers->f | PORT_FLAG_C);
}
