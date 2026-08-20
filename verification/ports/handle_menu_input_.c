#include "port_state.h"

struct handle_menu_input_state {
    struct cpu_register_state registers;
    port_u8 joy5;
    port_u8 menu_joypad_poll_count;
    port_u8 menu_wrapping_enabled;
    port_u8 current_menu_item;
    port_u8 max_menu_item;
    port_u8 check_for_180_degree_turn;
    port_u8 anim_counter;
    port_u8 menu_watched_keys;
};

#define PAD_UP 0x40u
#define PAD_DOWN 0x80u

/* Port of HandleMenuInput_ in home/window.asm. UI, timing, joypad-refresh,
 * and sound calls are represented by the explicit menu state. */
__attribute__((noinline, used)) void
port_handle_menu_input_(struct handle_menu_input_state *state)
{
    port_u8 joy = state->joy5;
    state->anim_counter = 0;
    if (joy == 0) {
        while (state->menu_joypad_poll_count != 0)
            state->menu_joypad_poll_count--;
        state->menu_wrapping_enabled = 0;
        state->registers.a = 0;
        return;
    }
    state->check_for_180_degree_turn = 0;
    if (joy & PAD_UP) {
        if (state->current_menu_item != 0)
            state->current_menu_item--;
        else if (state->menu_wrapping_enabled)
            state->current_menu_item = state->max_menu_item;
    } else if (joy & PAD_DOWN) {
        state->current_menu_item++;
        if (state->current_menu_item > state->max_menu_item)
            state->current_menu_item = state->menu_wrapping_enabled ? 0 : state->max_menu_item;
    }
    state->menu_wrapping_enabled = 0;
    state->registers.a = joy;
}
