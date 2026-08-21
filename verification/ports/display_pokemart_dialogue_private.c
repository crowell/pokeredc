#include "port_state.h"

struct display_pokemart_private_state {
	struct cpu_register_state registers;
	port_u8 list_scroll;
	port_u8 saved_scroll;
	port_u8 bought_sold;
	port_u8 current_menu;
	port_u8 player_number;
	port_u8 print_prices;
	port_u8 textbox_id;
};

/* Port of DisplayPokemartDialogue_ through first money-box setup. */
__attribute__((noinline, used)) void
port_display_pokemart_dialogue_private(
	struct display_pokemart_private_state *state)
{
	state->saved_scroll = state->list_scroll;
	state->bought_sold = 0;
	state->list_scroll = 0;
	state->current_menu = 0;
	state->player_number = 0;
	state->print_prices = 1;
	state->textbox_id = 0x13;
	state->registers.a = 0x13;
	state->registers.f = 0;
}
