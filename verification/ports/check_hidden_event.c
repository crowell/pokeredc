#include "port_state.h"

struct hidden_event_check_state {
    struct cpu_register_state registers;
    port_u8 joy_held;
    port_u8 didnt_find_any_hidden_event;
    port_u8 interacted_with_bookshelf;
    port_u8 saved_bank;
    port_u8 item_already_found;
    port_u8 rom_bank;
    port_u8 loaded_rom_bank;
};

/* Port of CheckForHiddenEventOrBookshelfOrCardKeyDoor in
 * home/hidden_events.asm. The hidden-event and bookshelf call boundaries are
 * represented by their explicit result bytes; the entry ROM bank is restored
 * on every path. */
__attribute__((noinline, used)) void
port_check_for_hidden_event_or_bookshelf_or_card_key_door(
    struct hidden_event_check_state *state)
{
    port_u8 result;
    if ((state->joy_held & 1u) == 0) {
        result = 0xff;
    } else if (state->didnt_find_any_hidden_event == 0) {
        result = 0;
    } else if (state->interacted_with_bookshelf == 0) {
        result = 0;
    } else {
        result = 0xff;
    }
    state->item_already_found = result;
    state->rom_bank = state->saved_bank;
    state->loaded_rom_bank = state->saved_bank;
}
