#include "port_state.h"

struct print_safari_zone_battle_text_private_state {
	struct cpu_register_state registers;
	port_u8 bait_factor;
	port_u8 rock_factor;
};

static port_u8
	safari_dec_flags(port_u8 old_value)
{
	port_u8 result = (port_u8)(old_value - 1);
	return (port_u8)(PORT_FLAG_N |
		((port_u8)(result == 0) * PORT_FLAG_Z) |
		((port_u8)((old_value & 0x0f) == 0) * PORT_FLAG_H));
}

/* Port of PrintSafariZoneBattleText through its bait/rock text selection. */
__attribute__((noinline, used)) void
port_print_safari_zone_battle_text_private(
	struct print_safari_zone_battle_text_private_state *state)
{
	port_u8 old_value;
	if (state->bait_factor != 0) {
		old_value = state->bait_factor;
		state->bait_factor = (port_u8)(old_value - 1);
		state->registers.a = old_value;
		state->registers.h = 0x42;
		state->registers.l = 0xa7;
		state->registers.f = safari_dec_flags(old_value);
		return;
	}
	/* .no_bait decrements HL to wSafariEscapeFactor, then returns without
	 * touching it when the escape factor is zero. */
	state->registers.h = 0xcc;
	state->registers.l = 0xe8;
	old_value = state->rock_factor;
	state->registers.a = old_value;
	if (old_value == 0) {
		state->registers.f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_H);
		return;
	}
	state->rock_factor = (port_u8)(old_value - 1);
	state->registers.f = safari_dec_flags(old_value);
	/* SafariZoneAngryText is loaded before the catch-rate refresh, so it is
	 * also the final HL value when the decrement reaches zero. */
	state->registers.h = 0x42;
	state->registers.l = 0xac;
}
