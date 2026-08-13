#include "port_state.h"

/* Port of InitOptions in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_init_options(struct init_options_state *state)
{
	state->letter_printing_delay_flags = 1;
	state->registers.a = 3;
	state->options = 3;
}

/* Port of DiscardButtonPresses in engine/joypad.asm. */
__attribute__((noinline, used)) void
port_discard_button_presses(struct discard_buttons_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->joy_held = 0;
	state->joy_pressed = 0;
	state->joy_released = 0;
}

/* Port of InitYesNoTextBoxParameters in home/yes_no.asm. */
__attribute__((noinline, used)) void
port_init_yes_no_text_box_parameters(struct yes_no_parameters_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->two_option_menu_id = 0;
	state->registers.h = 0xc4;
	state->registers.l = 0x3a;
	state->registers.b = 8;
	state->registers.c = 15;
}

/* Port of ResetUsingStrengthOutOfBattleBit in home/overworld.asm. */
__attribute__((noinline, used)) void
port_reset_using_strength_out_of_battle_bit(struct reset_strength_state *state)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x28;
	state->status_flags1 &= (port_u8)~1;
}

/* Port of StartNewGame through the shared StartNewGameDebug tail. */
__attribute__((noinline, used)) void
port_start_new_game(struct reset_strength_state *state)
{
	state->registers.h = 0xd7;
	state->registers.l = 0x32;
	state->status_flags1 &= (port_u8)~2;
}
