#include "port_state.h"

void port_wait_for_sound_to_finish(struct wait_for_sound_state *);
void port_play_sound(struct play_sound_state *);

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

/* Port of PlayApplyingAttackSound in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_play_applying_attack_sound(struct play_applying_attack_sound_state *state)
{
	struct wait_for_sound_state wait;
	port_u8 multiplier;
	port_u8 frequency;
	port_u8 tempo;
	port_u8 sound;
	port_u8 index;

	wait.registers = state->sound.registers;
	wait.low_health_alarm = state->sound.low_health_alarm;
	for (index = 0; index < 3; index++)
		wait.channel_sound_ids[index] = state->sound.channel_sound_ids[index];
	port_wait_for_sound_to_finish(&wait);
	state->sound.registers = wait.registers;
	for (index = 0; index < 3; index++)
		state->sound.channel_sound_ids[index] = wait.channel_sound_ids[index];

	multiplier = state->damage_multipliers & 0x7f;
	state->sound.registers.a = multiplier;
	state->sound.registers.f = PORT_FLAG_H;
	if (multiplier == 0) {
		state->sound.registers.f |= PORT_FLAG_Z;
		return;
	}

	state->sound.registers.f = cp_flags(multiplier, 10);
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
	state->sound.registers.a = sound;
	state->sound.registers.c = sound;
	state->sound.registers.b = tempo;
	port_play_sound(&state->sound);
}
