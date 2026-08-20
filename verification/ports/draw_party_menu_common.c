#include "port_state.h"

struct draw_party_menu_common_state {
    struct cpu_register_state registers;
    port_u8 rom_bank;
    port_u8 bankswitch_called;
};

#define BANK_REDRAW_PARTY_MENU 4u

/* Port of DrawPartyMenuCommon in home/pokemon.asm. The indirect JP (HL)
 * boundary is represented by bankswitch_called; the selected bank is explicit
 * state rather than a raw hardware address. */
__attribute__((noinline, used)) void
port_draw_party_menu_common(struct draw_party_menu_common_state *state)
{
    state->registers.b = BANK_REDRAW_PARTY_MENU;
    state->rom_bank = BANK_REDRAW_PARTY_MENU;
    state->bankswitch_called = 1;
}
