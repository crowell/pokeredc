#include "port_state.h"

#define W_NAMING_SCREEN_TYPE 0xd07du
#define W_PLAYER_NAME 0xd158u
#define W_CURRENT_MENU_ITEM 0xcc26u

void port_oak_speech_slide_pic_right(struct cpu_register_state *);
void port_display_intro_name_text_box(struct cpu_register_state *, port_u8 *);

/* Port of ChoosePlayerName through the DisplayNamingScreen call boundary in
 * engine/movie/oak_speech/oak_speech2.asm. The default-name and interactive
 * submission continuations remain outside this proof domain. */
__attribute__((noinline, used)) void
port_choose_player_name(struct cpu_register_state *state, port_u8 *memory)
{
	port_oak_speech_slide_pic_right(state);
	state->d = 0x6a;
	state->e = 0xa8;
	port_display_intro_name_text_box(state, memory);

	/* DisplayIntroNameTextBox's HandleMenuInput boundary returns the custom
	 * name selection for this proof contract. */
	if (memory[W_CURRENT_MENU_ITEM] == 0) {
		state->h = (port_u8)(W_PLAYER_NAME >> 8);
		state->l = (port_u8)W_PLAYER_NAME;
		state->a = 0;
		state->f = PORT_FLAG_Z;
		memory[W_NAMING_SCREEN_TYPE] = 0;
	}
}
