#include "port_state.h"

__attribute__((noinline, used)) void
port_load_mon_party_sprite_gfx_begin(struct mon_party_gfx_entry_state *state)
{
	state->registers.h = 0x57;
	state->registers.l = 0xc0;
	state->registers.a = 0x1c;
	state->dispatched = 1;
}

/* Port of LoadMonPartySpriteGfx in engine/gfx/mon_icons.asm. */
__attribute__((noinline, used)) void
port_load_mon_party_sprite_gfx(struct mon_party_gfx_entry_state *state,
	const struct cpu_register_state *callback_registers)
{
	port_load_mon_party_sprite_gfx_begin(state);
	/* Fallthrough into LoadAnimSpriteGfx is an arbitrary continuation. */
	state->registers = *callback_registers;
}
