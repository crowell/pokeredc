#include "port_state.h"

struct play_applying_attack_sound_state {
	struct cpu_register_state registers;
	port_u8 damage_multipliers;
	port_u8 frequency_modifier;
	port_u8 tempo_modifier;
};

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of PlayApplyingAttackSound through its PlaySound call boundary. */
__attribute__((noinline, used)) void
port_play_applying_attack_sound(struct play_applying_attack_sound_state *state)
{
	port_u8 multiplier = state->damage_multipliers & 0x7f;
	port_u8 frequency;
	port_u8 tempo;
	port_u8 sound;

	state->registers.a = multiplier;
	if (multiplier == 0) {
		state->registers.f = PORT_FLAG_Z;
		return;
	}

	state->registers.f = cp_flags(multiplier, 10);
	if (multiplier == 10) {
		frequency = 0x20;
		tempo = 0x30;
		sound = 0xa6;
	} else if (multiplier > 10) {
		frequency = 0xe0;
		tempo = 0xff;
		sound = 0xb0;
	} else {
		frequency = 0x50;
		tempo = 0x01;
		sound = 0xa7;
	}

	state->frequency_modifier = frequency;
	state->tempo_modifier = tempo;
	state->registers.a = sound;
	state->registers.c = sound;
	state->registers.b = tempo;
}
