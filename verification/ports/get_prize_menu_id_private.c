#include "port_state.h"

struct get_prize_menu_id_private_state {
	struct cpu_register_state registers;
	port_u8 text_id;
	port_u8 which_prize_window;
};

/* Port of GetPrizeMenuId through prize-window selection. */
__attribute__((noinline, used)) void
port_get_prize_menu_id_private(struct get_prize_menu_id_private_state *state)
{
	port_u8 relative = (port_u8)(state->text_id - 3);
	state->registers.a = relative;
	state->which_prize_window = relative;
}
