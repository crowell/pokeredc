#include "joypad_port.h"

#define POKEMART_GREETING_TEXT 0x2a55u
#define DISPLAY_POKEMART_DIALOGUE_BANK 1u
#define DISPLAY_POKEMART_DIALOGUE 0x6c20u
#define PRICED_ITEM_LIST_MENU 2u
#define W_LIST_MENU_ID 0xcf94u
#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define W_TEXT_BOX_ID 0xd125u

struct display_pokemart_private_state;
void port_print_text(struct cpu_register_state *, port_u8 *);
void port_load_item_list(struct load_item_list_state *, port_u8 *);
void port_display_pokemart_dialogue_private(
	struct display_pokemart_private_state *);
void port_after_displaying_text_id(
	struct after_displaying_text_id_state *, port_u8 *);

struct pokemart_private_register_state {
	struct cpu_register_state registers;
	port_u8 list_scroll;
	port_u8 saved_scroll;
	port_u8 bought_sold;
	port_u8 current_menu;
	port_u8 player_number;
	port_u8 print_prices;
	port_u8 textbox_id;
};

/* Port of DisplayPokemartDialogue in home/text_script.asm. */
__attribute__((noinline, used)) void
port_display_pokemart_dialogue(struct display_pokemart_dialogue_state *state,
	port_u8 *memory)
{
	struct load_item_list_state item_list = {0};
	struct pokemart_private_register_state private_state = {0};
	struct after_displaying_text_id_state after = {0};
	port_u8 saved_h = state->registers.h;
	port_u8 saved_l = state->registers.l;
	port_u8 saved_bank;
	port_u8 saved_f;

	/* push hl; ld hl, PokemartGreetingText; call PrintText; pop hl */
	state->registers.h = (port_u8)(POKEMART_GREETING_TEXT >> 8);
	state->registers.l = (port_u8)POKEMART_GREETING_TEXT;
	port_print_text(&state->registers, memory);
	state->registers.h = saved_h;
	state->registers.l = saved_l;

	/* inc hl; call LoadItemList */
	{
		port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
	}
	item_list.registers = state->registers;
	port_load_item_list(&item_list, memory);
	state->registers = item_list.registers;

	state->registers.a = PRICED_ITEM_LIST_MENU;
	state->list_menu_id = PRICED_ITEM_LIST_MENU;
	memory[W_LIST_MENU_ID] = state->list_menu_id;
	(void)W_UPDATE_SPRITES_ENABLED;

	/* homecall DisplayPokemartDialogue_: preserve AF and the current bank. */
	saved_bank = state->loaded_rom_bank;
	saved_f = state->registers.f;
	private_state.registers = state->registers;
	private_state.registers.a = DISPLAY_POKEMART_DIALOGUE_BANK;
	private_state.list_scroll = state->private_list_scroll;
	private_state.saved_scroll = state->private_saved_scroll;
	private_state.bought_sold = state->private_bought_sold;
	private_state.current_menu = state->private_current_menu;
	private_state.player_number = state->private_player_number;
	private_state.print_prices = state->private_print_prices;
	private_state.textbox_id = state->private_textbox_id;
	state->loaded_rom_bank = DISPLAY_POKEMART_DIALOGUE_BANK;
	state->romb = DISPLAY_POKEMART_DIALOGUE_BANK;
	port_display_pokemart_dialogue_private(
		(struct display_pokemart_private_state *)&private_state);
	state->registers = private_state.registers;
	state->private_list_scroll = private_state.list_scroll;
	state->private_saved_scroll = private_state.saved_scroll;
	state->private_bought_sold = private_state.bought_sold;
	state->private_current_menu = private_state.current_menu;
	state->private_player_number = private_state.player_number;
	state->private_print_prices = private_state.print_prices;
	state->private_textbox_id = private_state.textbox_id;
	memory[W_TEXT_BOX_ID] = state->private_textbox_id;
	state->registers.a = saved_bank;
	state->registers.f = saved_f;
	state->loaded_rom_bank = saved_bank;
	state->romb = saved_bank;

	after.registers = state->registers;
	for (port_u8 i = 0; i < 8u; ++i)
		after.joy_inputs[i] = state->joy_inputs[i];
	after.joy_input_count = state->joy_input_count;
	port_after_displaying_text_id(&after, memory);
	state->registers = after.registers;
}
