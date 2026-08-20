#include "port_state.h"

/* Port of PrintListMenuEntries.printCancelMenuItem in home/list_menu.asm.
 *
 * ld de, $2f97; jp $1955. LD DE and JP preserve F; the local JP is the boundary. */

#define PRINT_LIST_MENU_ENTRIES_PRINT_CANCEL_MENU_ITEM_DE 0x2f97u

__attribute__((noinline, used)) void
port_print_list_menu_entries_print_cancel_menu_item(
    struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(PRINT_LIST_MENU_ENTRIES_PRINT_CANCEL_MENU_ITEM_DE >> 8);
    state->e = (port_u8)(PRINT_LIST_MENU_ENTRIES_PRINT_CANCEL_MENU_ITEM_DE & 0xff);
}
