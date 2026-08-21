#include "port_state.h"

/* Port of DisplayLinkBattleVersusTextBox through TextBoxBorder. */
__attribute__((noinline, used)) void
port_display_link_battle_versus_text_box(struct cpu_register_state *registers)
{
	registers->h = 0xc3;
	registers->l = 0xf3;
	registers->b = 7;
	registers->c = 12;
}
