#include "port_state.h"

/* Port of DisplayEffectiveness in engine/battle/display_effectiveness.asm.
 *
 * Displays "Super effective!", "Not very effective...", or nothing depending on
 * the damage multiplier. Returns if multiplier is exactly 1.0 (EFFECTIVE),
 * otherwise sets HL to the appropriate text pointer (caller must call PrintText).
 *
 * Input: [wDamageMultipliers] (byte)
 * Output: if effective, returns with HL unchanged; if not effective, HL = text pointer */

#define W_DAMAGE_MULTIPLIERS 0xD05Bu
#define EFFECTIVE 10u
#define SUPER_EFFECTIVE_TEXT 0x7B8Eu
#define NOT_VERY_EFFECTIVE_TEXT 0x7B93u

__attribute__((noinline, used)) void
port_display_effectiveness(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 mult = memory[W_DAMAGE_MULTIPLIERS] & 0x7Fu;
	if (mult == EFFECTIVE) {
		return;
	}
	if (mult < EFFECTIVE) {
		state->h = (port_u8)(NOT_VERY_EFFECTIVE_TEXT >> 8);
		state->l = (port_u8)NOT_VERY_EFFECTIVE_TEXT;
	} else {
		state->h = (port_u8)(SUPER_EFFECTIVE_TEXT >> 8);
		state->l = (port_u8)SUPER_EFFECTIVE_TEXT;
	}
}