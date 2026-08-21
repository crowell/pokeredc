#include "port_state.h"

struct display_mon_front_sprite_private_state {
	struct cpu_register_state registers;
	port_u8 auto_bg_transfer;
	port_u8 wy;
	port_u8 text_box_id;
};

/* Port of DisplayMonFrontSpriteInBox through popup-box setup. */
__attribute__((noinline, used)) void
port_display_mon_front_sprite_in_box_private(
	struct display_mon_front_sprite_private_state *state)
{
	state->registers.a = 0x11;
	state->registers.f = 0;
	state->auto_bg_transfer = 1;
	state->wy = 0;
	state->text_box_id = 0x11;
}
