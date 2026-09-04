#include "port_state.h"

#define W_NAMING_SCREEN_TYPE 0xd07du
#define W_RIVAL_NAME 0xd34au
#define W_CURRENT_MENU_ITEM 0xcc26u

void port_oak_speech_slide_pic_right(struct cpu_register_state *);
void port_display_intro_name_text_box(struct cpu_register_state *, port_u8 *);

/* Port of ChooseRivalName through the DisplayNamingScreen call boundary in
 * engine/movie/oak_speech/oak_speech2.asm. The default-name and interactive
 * submission continuations remain outside this proof domain. */
__attribute__((noinline, used)) void
port_choose_rival_name(struct cpu_register_state *state, port_u8 *memory)
{
	port_oak_speech_slide_pic_right(state);
	state->d = 0x6a;
	state->e = 0xbe;
	port_display_intro_name_text_box(state, memory);

	if (memory[W_CURRENT_MENU_ITEM] == 0) {
		state->h = (port_u8)(W_RIVAL_NAME >> 8);
		state->l = (port_u8)W_RIVAL_NAME;
		state->a = 1;
		state->f = 0;
		memory[W_NAMING_SCREEN_TYPE] = 1;
	}
}
