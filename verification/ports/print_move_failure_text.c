#include "port_state.h"

struct print_move_failure_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 jump_kick_path;
};

#define W_PLAYER_MOVE_EFFECT 0xcfd3u
#define W_ENEMY_MOVE_EFFECT 0xcfcdU
#define W_DAMAGE_MULTIPLIERS 0xd05bu
#define W_CRITICAL_HIT_OR_OHKO 0xd05eu
#define W_DAMAGE 0xd0d7u
#define DOESNT_AFFECT_TEXT 0x5c57u
#define ATTACK_MISSED_TEXT 0x5c42u
#define UNAFFECTED_TEXT 0x5c4cu
#define KEPT_GOING_AND_CRASHED_TEXT 0x5c47u
#define JUMP_KICK_EFFECT 0x2du
#define EFFECTIVENESS_MASK 0x7fu

void port_print_text(struct cpu_register_state *, port_u8 *);

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;
	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of PrintMoveFailureText through Jump Kick recoil calculation and the
 * second crash-text PrintText call.  Screen shake and target damage remain
 * explicit boundaries because their downstream effects are partial. */
__attribute__((noinline, used)) void
port_print_move_failure_text(struct print_move_failure_state *state,
	port_u8 *memory)
{
	port_u16 effect_address = state->whose_turn == 0u ?
		W_PLAYER_MOVE_EFFECT : W_ENEMY_MOVE_EFFECT;
	state->registers.d = (port_u8)(effect_address >> 8);
	state->registers.e = (port_u8)effect_address;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;

	port_u16 text = DOESNT_AFFECT_TEXT;
	if ((memory[W_DAMAGE_MULTIPLIERS] & EFFECTIVENESS_MASK) != 0u) {
		text = ATTACK_MISSED_TEXT;
		if (memory[W_CRITICAL_HIT_OR_OHKO] == 0xffu)
			text = UNAFFECTED_TEXT;
	}
	state->registers.h = (port_u8)(text >> 8);
	state->registers.l = text;
	port_print_text(&state->registers, memory);
	memory[W_CRITICAL_HIT_OR_OHKO] = 0u;

	port_u8 effect = memory[effect_address];
	state->registers.a = effect;
	state->registers.f = compare_flags(effect, JUMP_KICK_EFFECT);
	state->jump_kick_path = effect == JUMP_KICK_EFFECT ? 1u : 0u;
	if (effect == JUMP_KICK_EFFECT) {
		port_u16 damage = (port_u16)(((port_u16)memory[W_DAMAGE] << 8) |
			memory[W_DAMAGE + 1u]);
		damage = (port_u16)(damage >> 3);
		if (damage == 0u)
			damage = 1u;
		memory[W_DAMAGE] = (port_u8)(damage >> 8);
		memory[W_DAMAGE + 1u] = (port_u8)damage;
		/* OR B after the three SRL/RR pairs leaves only Z set for a
		 * zero quotient; the zero case then INC A, which clears Z again. */
		state->registers.f = 0u;
		state->registers.h = (port_u8)(KEPT_GOING_AND_CRASHED_TEXT >> 8);
		state->registers.l = (port_u8)KEPT_GOING_AND_CRASHED_TEXT;
		port_print_text(&state->registers, memory);
		state->registers.b = 4u;
		state->registers.a = 0x24u;
	}
}
