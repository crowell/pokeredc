#include "port_state.h"

static void
audio_set_is_cry(struct cpu_register_state *registers, port_u8 sound_id)
{
	registers->a = sound_id;
	/* Carry set when sound_id >= 0x14 and sound_id != 0x86; carry clear
	 * otherwise. The assembly's .yes and .no both end in `ret`, so no Z flag
	 * is ever produced; the prior port wrongly set Z for 0x86 and cleared
	 * carry for >0x86. */
	if (registers->a >= 0x14 && registers->a != 0x86) {
		registers->f = PORT_FLAG_C;
	} else {
		registers->f = 0;
	}
}

static void
audio_is_cry(struct audio_is_cry_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
}

/* Ports of the byte-identical IsCry leaf in all three audio engines. */
__attribute__((noinline, used)) void
port_audio1_is_cry(struct audio_is_cry_state *state)
{
	audio_is_cry(state);
}

__attribute__((noinline, used)) void
port_audio2_is_cry(struct audio_is_cry_state *state)
{
	audio_is_cry(state);
}

__attribute__((noinline, used)) void
port_audio3_is_cry(struct audio_is_cry_state *state)
{
	audio_is_cry(state);
}

/* Port of the Audio2-only IsBattleSFX leaf. */
__attribute__((noinline, used)) void
port_audio2_is_battle_sfx(struct audio_battle_sfx_state *state)
{
	state->registers.a = state->channel8_sound_id;
	state->registers.b = state->registers.a;
	state->registers.a = state->channel5_sound_id;
	state->registers.a |= state->registers.b;
	if (state->registers.a >= 0x9d && state->registers.a < 0xea) {
		state->registers.f = PORT_FLAG_C;
	} else if (state->registers.a == 0xea) {
		state->registers.f = PORT_FLAG_Z;
	} else {
		state->registers.f = 0;
	}
}

static void
audio_enable_channel_output(
	struct audio_channel_output_state *state,
	port_u16 enable_masks_address,
	port_u16 disable_masks_address)
{
	static const port_u8 enable_masks[8] = {
		0x11, 0x22, 0x44, 0x88, 0x11, 0x22, 0x44, 0x88,
	};
	static const port_u8 disable_masks[8] = {
		0xee, 0xdd, 0xbb, 0x77, 0xee, 0xdd, 0xbb, 0x77,
	};
	port_u8 channel = state->registers.c;
	port_u8 output = state->audio_terminal | enable_masks[channel];
	port_u16 hl = enable_masks_address + channel;
	port_u8 apply_panning = 0;

	state->registers.b = 0;
	state->registers.d = output;
	state->registers.a = channel;
	if (channel == 7) {
		apply_panning = 1;
	} else if (channel < 4) {
		hl = 0xc02a + channel;
		state->registers.a = state->sfx_sound_ids[channel];
		if (state->registers.a == 0)
			apply_panning = 1;
	} else {
		state->registers.f = channel == 4 ?
			PORT_FLAG_Z | PORT_FLAG_N : PORT_FLAG_N;
	}

	if (apply_panning) {
		output = (state->audio_terminal & disable_masks[channel]) |
			(state->stereo_panning & enable_masks[channel]);
		state->registers.d = output;
		state->registers.f = output == 0 ? PORT_FLAG_Z : 0;
		hl = disable_masks_address + channel;
	} else if (channel < 4) {
		state->registers.f = PORT_FLAG_H;
	}

	state->registers.a = state->registers.d;
	state->audio_terminal = state->registers.a;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Ports of EnableChannelOutput in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_enable_channel_output(struct audio_channel_output_state *state)
{
	audio_enable_channel_output(state, 0x5b27, 0x5b1f);
}

__attribute__((noinline, used)) void
port_audio2_enable_channel_output(struct audio_channel_output_state *state)
{
	audio_enable_channel_output(state, 0x62e6, 0x62de);
}

__attribute__((noinline, used)) void
port_audio3_enable_channel_output(struct audio_channel_output_state *state)
{
	audio_enable_channel_output(state, 0x5b9b, 0x5b93);
}

static void
audio_multiply_add(struct cpu_register_state *registers)
{
	port_u8 multiplier = registers->a;
	port_u16 multiplicand =
		((port_u16)registers->d << 8) | registers->e;
	port_u16 result = registers->l;

	do {
		if (multiplier & 1)
			result += multiplicand;
		multiplier >>= 1;
		multiplicand <<= 1;
	} while (multiplier != 0);

	registers->a = 0;
	registers->f = PORT_FLAG_Z | PORT_FLAG_H;
	registers->d = (port_u8)(multiplicand >> 8);
	registers->e = (port_u8)multiplicand;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Ports of MultiplyAdd in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_multiply_add(struct cpu_register_state *registers)
{
	audio_multiply_add(registers);
}

__attribute__((noinline, used)) void
port_audio2_multiply_add(struct cpu_register_state *registers)
{
	audio_multiply_add(registers);
}

__attribute__((noinline, used)) void
port_audio3_multiply_add(struct cpu_register_state *registers)
{
	audio_multiply_add(registers);
}

static port_u8
audio_add_flags(port_u8 left, port_u8 right)
{
	port_u8 result = left + right;
	port_u8 flags = 0;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		flags |= PORT_FLAG_H;
	if ((port_u16)left + right > 0xff)
		flags |= PORT_FLAG_C;
	return flags;
}

static void
audio_get_register_pointer(struct cpu_register_state *registers)
{
	static const port_u8 bases[8] = {
		0x10, 0x15, 0x1a, 0x1f, 0x10, 0x15, 0x1a, 0x1f,
	};
	port_u8 base = bases[registers->c];

	registers->a = base + registers->b;
	registers->f = audio_add_flags(base, registers->b);
	registers->l = registers->a;
	registers->h = 0xff;
}

/* Ports of GetRegisterPointer in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_get_register_pointer(struct cpu_register_state *registers)
{
	audio_get_register_pointer(registers);
}

__attribute__((noinline, used)) void
port_audio2_get_register_pointer(struct cpu_register_state *registers)
{
	audio_get_register_pointer(registers);
}

__attribute__((noinline, used)) void
port_audio3_get_register_pointer(struct cpu_register_state *registers)
{
	audio_get_register_pointer(registers);
}

static void
audio_calculate_frequency(
	struct cpu_register_state *registers, port_u16 pitches_address)
{
	static const port_u16 pitches[12] = {
		0xf82c, 0xf89d, 0xf907, 0xf96b, 0xf9ca, 0xfa23,
		0xfa77, 0xfac7, 0xfb12, 0xfb58, 0xfb9b, 0xfbda,
	};
	port_u8 note = registers->a;
	port_u8 octave = registers->b;
	port_u16 frequency = pitches[note];
	port_u8 high;

	while (octave != 7) {
		frequency = (frequency >> 1) | 0x8000;
		octave++;
	}
	high = (port_u8)(frequency >> 8);
	registers->a = high + 8;
	registers->f = audio_add_flags(8, high);
	registers->d = registers->a;
	registers->e = (port_u8)frequency;
	registers->h = (port_u8)((pitches_address + (port_u16)note * 2 + 1) >> 8);
	registers->l = (port_u8)(pitches_address + (port_u16)note * 2 + 1);
}

/* Ports of CalculateFrequency in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_calculate_frequency(struct cpu_register_state *registers)
{
	audio_calculate_frequency(registers, 0x5b2f);
}

__attribute__((noinline, used)) void
port_audio2_calculate_frequency(struct cpu_register_state *registers)
{
	audio_calculate_frequency(registers, 0x62ee);
}

__attribute__((noinline, used)) void
port_audio3_calculate_frequency(struct cpu_register_state *registers)
{
	audio_calculate_frequency(registers, 0x5ba3);
}

static void
audio_apply_duty_cycle_pattern(struct audio_duty_pattern_state *state)
{
	static const port_u8 bases[8] = {
		0x10, 0x15, 0x1a, 0x1f, 0x10, 0x15, 0x1a, 0x1f,
	};
	port_u8 channel = state->registers.c;
	port_u8 pattern = state->duty_patterns[channel];
	port_u8 hardware_index = channel & 3;

	state->registers.b = 0;
	pattern = (port_u8)((pattern << 2) | (pattern >> 6));
	state->duty_patterns[channel] = pattern;
	state->registers.d = pattern & 0xc0;
	state->registers.b = 1;
	state->registers.a =
		(state->hardware_duty_registers[hardware_index] & 0x3f) |
		state->registers.d;
	state->hardware_duty_registers[hardware_index] = state->registers.a;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0xff;
	state->registers.l = bases[channel] + 1;
}

/* Ports of ApplyDutyCyclePattern in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_apply_duty_cycle_pattern(struct audio_duty_pattern_state *state)
{
	audio_apply_duty_cycle_pattern(state);
}

__attribute__((noinline, used)) void
port_audio2_apply_duty_cycle_pattern(struct audio_duty_pattern_state *state)
{
	audio_apply_duty_cycle_pattern(state);
}

__attribute__((noinline, used)) void
port_audio3_apply_duty_cycle_pattern(struct audio_duty_pattern_state *state)
{
	audio_apply_duty_cycle_pattern(state);
}

static void
audio_apply_duty_cycle_and_sound_length(struct audio_duty_length_state *state)
{
	static const port_u8 bases[8] = {
		0x10, 0x15, 0x1a, 0x1f, 0x10, 0x15, 0x1a, 0x1f,
	};
	port_u8 channel = state->registers.c;
	port_u8 length = state->note_delays[channel];
	port_u8 hardware_index = channel & 3;

	state->registers.b = 0;
	state->registers.d = length;
	state->registers.a = channel;
	if (channel != 2 && channel != 6) {
		length = (length & 0x3f) | state->duty_cycles[channel];
		state->registers.d = length;
	}
	state->registers.b = 1;
	state->registers.a = bases[channel] + 1;
	state->registers.f = audio_add_flags(bases[channel], 1);
	state->registers.h = 0xff;
	state->registers.l = state->registers.a;
	state->hardware_duty_registers[hardware_index] = length;
}

/* Ports of ApplyDutyCycleAndSoundLength in all three audio-engine copies. */
__attribute__((noinline, used)) void
port_audio1_apply_duty_cycle_and_sound_length(struct audio_duty_length_state *state)
{
	audio_apply_duty_cycle_and_sound_length(state);
}

__attribute__((noinline, used)) void
port_audio2_apply_duty_cycle_and_sound_length(struct audio_duty_length_state *state)
{
	audio_apply_duty_cycle_and_sound_length(state);
}

__attribute__((noinline, used)) void
port_audio3_apply_duty_cycle_and_sound_length(struct audio_duty_length_state *state)
{
	audio_apply_duty_cycle_and_sound_length(state);
}

static port_u8
audio_cp_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static port_u8
audio_dec_flags(port_u8 old_flags, port_u8 value)
{
	port_u8 result = value - 1;
	port_u8 flags = (old_flags & PORT_FLAG_C) | PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((value & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	return flags;
}

static port_u8
audio_inc_flags(port_u8 old_flags, port_u8 value)
{
	port_u8 result = value + 1;
	port_u8 flags = old_flags & PORT_FLAG_C;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((value & 0x0f) == 0x0f)
		flags |= PORT_FLAG_H;
	return flags;
}

static port_u8
audio_sub_flags(port_u8 left, port_u8 right)
{
	port_u8 result = left - right;
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of the Audio2-only ResetCryModifiers leaf. */
__attribute__((noinline, used)) void
port_audio2_reset_cry_modifiers(struct audio_cry_modifiers_state *state)
{
	state->registers.a = state->registers.c;
	state->registers.f = audio_cp_flags(state->registers.a, 4);
	if (state->registers.a != 4)
		return;

	state->registers.a = state->low_health_alarm;
	state->registers.f = PORT_FLAG_H;
	if ((state->registers.a & 0x80) == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}

	state->registers.a = 0x80;
	state->registers.f = PORT_FLAG_Z;
	state->frequency_modifier = 0;
	state->tempo_modifier = 0x80;
}

static void
audio_apply_sfx_tempo(struct audio_sfx_tempo_state *state)
{
	port_u8 input;
	port_u8 result;

	state->registers.d = 0;
	input = state->tempo_modifier;
	result = input + 0x80;
	state->registers.a = result;
	state->registers.f = audio_add_flags(input, 0x80);
	if (state->registers.f & PORT_FLAG_C) {
		state->registers.d = 1;
		state->registers.f = PORT_FLAG_C;
	}
	state->sfx_tempo_low = result;
	state->registers.a = state->registers.d;
	state->sfx_tempo_high = state->registers.a;
}

static void
audio_set_default_sfx_tempo(struct audio_sfx_tempo_state *state)
{
	state->registers.a = 1;
	state->registers.f = PORT_FLAG_Z;
	state->sfx_tempo_low = 0;
	state->sfx_tempo_high = 1;
}

__attribute__((noinline, used)) void
port_audio1_set_sfx_tempo(struct audio_sfx_tempo_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_sfx_tempo(state);
	else
		audio_set_default_sfx_tempo(state);
}

__attribute__((noinline, used)) void
port_audio2_set_sfx_tempo(struct audio_sfx_tempo_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if ((state->registers.f & PORT_FLAG_C) == 0) {
		state->registers.b = state->channel8_sound_id;
		state->registers.a = state->channel5_sound_id | state->registers.b;
		if (state->registers.a >= 0x9d && state->registers.a < 0xea) {
			state->registers.f = PORT_FLAG_C;
		} else if (state->registers.a == 0xea) {
			state->registers.f = PORT_FLAG_Z;
		} else {
			state->registers.f = 0;
		}
	}
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_sfx_tempo(state);
	else
		audio_set_default_sfx_tempo(state);
}

__attribute__((noinline, used)) void
port_audio3_set_sfx_tempo(struct audio_sfx_tempo_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_sfx_tempo(state);
	else
		audio_set_default_sfx_tempo(state);
}

static void
audio_apply_frequency_value(struct audio_frequency_modifier_state *state)
{
	port_u8 initial_e = state->registers.e;
	port_u8 initial_d = state->registers.d;
	port_u8 result = state->frequency_modifier + initial_e;
	port_u8 hardware_index = (port_u8)((state->registers.l - 0x14) / 5) * 2;

	state->registers.a = result;
	state->registers.f = audio_add_flags(state->frequency_modifier, initial_e);
	if (state->registers.f & PORT_FLAG_C) {
		state->registers.d = initial_d + 1;
		state->registers.f = PORT_FLAG_C;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((initial_d & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.e = result;
	state->hardware_frequency_registers[hardware_index] = result;
	state->hardware_frequency_registers[hardware_index + 1] = state->registers.d;
}

__attribute__((noinline, used)) void
port_audio1_apply_frequency_modifier(struct audio_frequency_modifier_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_frequency_value(state);
}

__attribute__((noinline, used)) void
port_audio2_apply_frequency_modifier(struct audio_frequency_modifier_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if ((state->registers.f & PORT_FLAG_C) == 0) {
		state->registers.b = state->channel8_sound_id;
		state->registers.a = state->channel5_sound_id | state->registers.b;
		if (state->registers.a >= 0x9d && state->registers.a < 0xea) {
			state->registers.f = PORT_FLAG_C;
		} else if (state->registers.a == 0xea) {
			state->registers.f = PORT_FLAG_Z;
		} else {
			state->registers.f = 0;
		}
	}
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_frequency_value(state);
}

__attribute__((noinline, used)) void
port_audio3_apply_frequency_modifier(struct audio_frequency_modifier_state *state)
{
	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if (state->registers.f & PORT_FLAG_C)
		audio_apply_frequency_value(state);
}

static const port_u8 audio_wave_patterns[3][6][16] = {
	{
		{0x02, 0x46, 0x8a, 0xce, 0xff, 0xfe, 0xed, 0xdc,
		 0xcb, 0xa9, 0x87, 0x65, 0x44, 0x33, 0x22, 0x11},
		{0x02, 0x46, 0x8a, 0xce, 0xef, 0xff, 0xfe, 0xee,
		 0xdd, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x22, 0x11},
		{0x13, 0x69, 0xbd, 0xee, 0xee, 0xff, 0xff, 0xed,
		 0xde, 0xff, 0xff, 0xee, 0xee, 0xdb, 0x96, 0x31},
		{0x02, 0x46, 0x8a, 0xcd, 0xef, 0xfe, 0xde, 0xff,
		 0xee, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		{0x01, 0x23, 0x45, 0x67, 0x8a, 0xcd, 0xee, 0xf7,
		 0x7f, 0xee, 0xdc, 0xa8, 0x76, 0x54, 0x32, 0x10},
		{0x21, 0xe2, 0x33, 0x28, 0xe1, 0x22, 0xff, 0xea,
		 0x10, 0x14, 0xdc, 0x10, 0xe3, 0x41, 0x51, 0x73},
	},
	{
		{0x02, 0x46, 0x8a, 0xce, 0xff, 0xfe, 0xed, 0xdc,
		 0xcb, 0xa9, 0x87, 0x65, 0x44, 0x33, 0x22, 0x11},
		{0x02, 0x46, 0x8a, 0xce, 0xef, 0xff, 0xfe, 0xee,
		 0xdd, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x22, 0x11},
		{0x13, 0x69, 0xbd, 0xee, 0xee, 0xff, 0xff, 0xed,
		 0xde, 0xff, 0xff, 0xee, 0xee, 0xdb, 0x96, 0x31},
		{0x02, 0x46, 0x8a, 0xcd, 0xef, 0xfe, 0xde, 0xff,
		 0xee, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		{0x01, 0x23, 0x45, 0x67, 0x8a, 0xcd, 0xee, 0xf7,
		 0x7f, 0xee, 0xdc, 0xa8, 0x76, 0x54, 0x32, 0x10},
		{0xec, 0x02, 0x20, 0x91, 0xc0, 0x07, 0x20, 0x81,
		 0xd0, 0x07, 0x20, 0x91, 0xc0, 0x07, 0x2c, 0xa1},
	},
	{
		{0x02, 0x46, 0x8a, 0xce, 0xff, 0xfe, 0xed, 0xdc,
		 0xcb, 0xa9, 0x87, 0x65, 0x44, 0x33, 0x22, 0x11},
		{0x02, 0x46, 0x8a, 0xce, 0xef, 0xff, 0xfe, 0xee,
		 0xdd, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x22, 0x11},
		{0x13, 0x69, 0xbd, 0xee, 0xee, 0xff, 0xff, 0xed,
		 0xde, 0xff, 0xff, 0xee, 0xee, 0xdb, 0x96, 0x31},
		{0x02, 0x46, 0x8a, 0xcd, 0xef, 0xfe, 0xde, 0xff,
		 0xee, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		{0x01, 0x23, 0x45, 0x67, 0x8a, 0xcd, 0xee, 0xf7,
		 0x7f, 0xee, 0xdc, 0xa8, 0x76, 0x54, 0x32, 0x10},
		{0x21, 0xe2, 0x33, 0x28, 0xe1, 0x22, 0xff, 0x22,
		 0xf7, 0x24, 0x22, 0xf7, 0x34, 0x24, 0xf7, 0x44},
	},
};

static void
audio_wave_apply_modifier(struct audio_wave_frequency_state *state, int battle_sfx)
{
	port_u8 applies;
	port_u8 result;
	port_u8 initial_d;
	port_u8 hardware_index = (state->registers.c & 3) * 2;

	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	applies = (state->registers.f & PORT_FLAG_C) != 0;
	if (!applies && battle_sfx) {
		state->registers.b = state->channel8_sound_id;
		state->registers.a = state->channel5_sound_id | state->registers.b;
		if (state->registers.a >= 0x9d && state->registers.a < 0xea) {
			state->registers.f = PORT_FLAG_C;
		} else if (state->registers.a == 0xea) {
			state->registers.f = PORT_FLAG_Z;
		} else {
			state->registers.f = 0;
		}
		applies = (state->registers.f & PORT_FLAG_C) != 0;
	}
	if (!applies)
		return;

	initial_d = state->registers.d;
	result = state->frequency_modifier + state->registers.e;
	state->registers.a = result;
	state->registers.f = audio_add_flags(
		state->frequency_modifier, state->registers.e);
	if (state->registers.f & PORT_FLAG_C) {
		state->registers.d = initial_d + 1;
		state->registers.f = PORT_FLAG_C;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((initial_d & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.e = result;
	state->hardware_frequency_registers[hardware_index] = result;
	state->hardware_frequency_registers[hardware_index + 1] = state->registers.d;
}

static void
audio_apply_wave_pattern_and_frequency(
	struct audio_wave_frequency_state *state, port_u8 variant)
{
	static const port_u8 bases[8] = {
		0x10, 0x15, 0x1a, 0x1f, 0x10, 0x15, 0x1a, 0x1f,
	};
	port_u8 channel = state->registers.c;
	port_u8 hardware_index = (channel & 3) * 2;
	port_u8 index;
	port_u8 i;

	if (channel == 2 || channel == 6) {
		index = channel == 2 ?
			state->music_wave_instrument : state->sfx_wave_instrument;
		if (index > 5)
			index = 5;
		for (i = 0; i != 16; i++)
			state->wave_ram[i] = audio_wave_patterns[variant][index][i];
		state->audio3_enable = 0x80;
	}

	state->registers.a = (state->registers.d | 0x80) & 0xc7;
	state->registers.d = state->registers.a;
	state->registers.b = 3;
	state->registers.a = bases[channel] + 3;
	state->registers.f = audio_add_flags(bases[channel], 3);
	state->registers.h = 0xff;
	state->registers.l = state->registers.a + 1;
	state->hardware_frequency_registers[hardware_index] = state->registers.e;
	state->hardware_frequency_registers[hardware_index + 1] = state->registers.d;

	if (variant == 1) {
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, 4);
		if (channel < 4)
			return;
		audio_wave_apply_modifier(state, 1);
	} else {
		audio_wave_apply_modifier(state, 0);
	}
}

__attribute__((noinline, used)) void
port_audio1_apply_wave_pattern_and_frequency(struct audio_wave_frequency_state *state)
{
	audio_apply_wave_pattern_and_frequency(state, 0);
}

__attribute__((noinline, used)) void
port_audio2_apply_wave_pattern_and_frequency(struct audio_wave_frequency_state *state)
{
	audio_apply_wave_pattern_and_frequency(state, 1);
}

__attribute__((noinline, used)) void
port_audio3_apply_wave_pattern_and_frequency(struct audio_wave_frequency_state *state)
{
	audio_apply_wave_pattern_and_frequency(state, 2);
}

static void
audio_go_back_one_command_if_cry(struct audio_command_rewind_state *state)
{
	port_u8 offset;
	port_u8 low;
	port_u8 high;
	port_u8 borrow;

	audio_set_is_cry(&state->registers, state->channel5_sound_id);
	if ((state->registers.f & PORT_FLAG_C) == 0)
		return;

	offset = state->registers.c * 2;
	state->registers.e = offset;
	state->registers.d = 0;
	low = state->command_pointers[offset];
	borrow = low == 0;
	low--;
	high = state->command_pointers[offset + 1] - borrow;
	state->command_pointers[offset] = low;
	state->command_pointers[offset + 1] = high;
	state->registers.a = high;
	state->registers.f = PORT_FLAG_C;
	if (high == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
}

__attribute__((noinline, used)) void
port_audio1_go_back_one_command_if_cry(struct audio_command_rewind_state *state)
{
	audio_go_back_one_command_if_cry(state);
}

__attribute__((noinline, used)) void
port_audio2_go_back_one_command_if_cry(struct audio_command_rewind_state *state)
{
	audio_go_back_one_command_if_cry(state);
}

__attribute__((noinline, used)) void
port_audio3_go_back_one_command_if_cry(struct audio_command_rewind_state *state)
{
	audio_go_back_one_command_if_cry(state);
}

static void
audio_get_next_music_byte(struct audio_next_music_byte_state *state)
{
	port_u8 offset = state->registers.c * 2;
	port_u16 pointer = state->command_pointers[offset] |
		((port_u16)state->command_pointers[offset + 1] << 8);

	state->registers.f = state->registers.c == 0 ? PORT_FLAG_Z : 0;
	state->registers.a = state->command_byte;
	pointer++;
	state->registers.d = (port_u8)(pointer >> 8);
	state->registers.e = (port_u8)pointer;
	state->command_pointers[offset] = state->registers.e;
	state->command_pointers[offset + 1] = state->registers.d;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
}

__attribute__((noinline, used)) void
port_audio1_get_next_music_byte(struct audio_next_music_byte_state *state)
{
	audio_get_next_music_byte(state);
}

__attribute__((noinline, used)) void
port_audio2_get_next_music_byte(struct audio_next_music_byte_state *state)
{
	audio_get_next_music_byte(state);
}

__attribute__((noinline, used)) void
port_audio3_get_next_music_byte(struct audio_next_music_byte_state *state)
{
	audio_get_next_music_byte(state);
}

static void
audio_apply_pitch_slide(struct audio_pitch_slide_state *state)
{
	static const port_u8 bases[8] = {
		0x10, 0x15, 0x1a, 0x1f, 0x10, 0x15, 0x1a, 0x1f,
	};
	port_u8 channel = state->registers.c;
	port_u8 hardware_index = (channel & 3) * 2;
	port_u16 current =
		((port_u16)state->current_frequency_high[channel] << 8) |
		state->current_frequency_low[channel];
	port_u16 target =
		((port_u16)state->target_frequency_high[channel] << 8) |
		state->target_frequency_low[channel];
	port_u16 candidate;
	port_u16 fractional;
	port_u8 reached;

	if (state->flags1[channel] & 0x20) {
		port_u8 old_fractional = state->frequency_steps_fractional[channel];

		state->frequency_steps_fractional[channel] = old_fractional << 1;
		candidate = current - state->frequency_steps[channel] -
			(old_fractional >> 7);
		reached = candidate < target;
		state->registers.a = (port_u8)(candidate >> 8);
		if ((candidate >> 8) == (target >> 8))
			state->registers.a = (port_u8)candidate;
	} else {
		fractional = state->current_frequency_fractional[channel] +
			state->frequency_steps_fractional[channel];
		state->current_frequency_fractional[channel] = (port_u8)fractional;
		candidate = current + state->frequency_steps[channel] +
			(fractional >> 8);
		reached = candidate > target;
		state->registers.a = state->target_frequency_high[channel];
		if ((candidate >> 8) == (target >> 8))
			state->registers.a = state->target_frequency_low[channel];
	}

	state->registers.d = (port_u8)(candidate >> 8);
	state->registers.e = (port_u8)candidate;
	if (reached) {
		state->flags1[channel] &= (port_u8)~0x30;
		state->registers.f = 0;
		state->registers.h = 0xc0;
		state->registers.l = 0x2e + channel;
		return;
	}

	state->current_frequency_low[channel] = state->registers.e;
	state->current_frequency_high[channel] = state->registers.d;
	state->registers.b = 3;
	state->registers.a = state->registers.e;
	state->registers.f = audio_add_flags(bases[channel], 3);
	state->registers.h = 0xff;
	state->registers.l = bases[channel] + 4;
	state->hardware_frequency_registers[hardware_index] = state->registers.e;
	state->hardware_frequency_registers[hardware_index + 1] = state->registers.d;
}

__attribute__((noinline, used)) void
port_audio1_apply_pitch_slide(struct audio_pitch_slide_state *state)
{
	audio_apply_pitch_slide(state);
}

__attribute__((noinline, used)) void
port_audio2_apply_pitch_slide(struct audio_pitch_slide_state *state)
{
	audio_apply_pitch_slide(state);
}

__attribute__((noinline, used)) void
port_audio3_apply_pitch_slide(struct audio_pitch_slide_state *state)
{
	audio_apply_pitch_slide(state);
}

static void
audio_init_pitch_slide_vars(struct audio_init_pitch_slide_state *state)
{
	port_u8 channel = state->registers.c;
	port_u8 current_high = state->registers.d;
	port_u8 current_low = state->registers.e;
	port_u8 target_high = state->target_frequency_high[channel];
	port_u8 target_low = state->target_frequency_low[channel];
	port_u8 divisor;
	port_u8 low_difference;
	port_u8 low_borrow;
	port_u8 adjusted_current_high;
	port_u8 high_difference;
	port_u16 difference;
	port_u16 quotient;
	port_u8 remainder;

	state->current_frequency_high[channel] = current_high;
	state->current_frequency_low[channel] = current_low;
	if (state->note_delays[channel] < state->length_modifiers[channel])
		divisor = 1;
	else
		divisor = state->note_delays[channel] -
			state->length_modifiers[channel];
	state->length_modifiers[channel] = divisor;

	low_borrow = current_low < target_low;
	low_difference = current_low - target_low;
	adjusted_current_high = current_high - low_borrow;
	high_difference = adjusted_current_high - target_high;
	if (adjusted_current_high >= target_high) {
		difference = ((port_u16)high_difference << 8) | low_difference;
		state->flags1[channel] |= 0x20;
	} else {
		port_u8 target_low_borrow = target_low < current_low;
		port_u8 buggy_current_high = current_high - target_low_borrow;

		difference = ((port_u16)(port_u8)(target_high - buggy_current_high) << 8) |
			(port_u8)(target_low - current_low);
		state->flags1[channel] &= (port_u8)~0x20;
	}

	quotient = difference / divisor;
	remainder = difference % divisor;
	state->registers.a = remainder;
	state->registers.d = (port_u8)(quotient + 1);
	state->registers.e = remainder - divisor;
	state->registers.b = 0;
	state->registers.f = remainder == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x8e + channel;
	state->frequency_steps[channel] = state->registers.d;
	state->frequency_steps_fractional[channel] = remainder;
	state->current_frequency_fractional[channel] = remainder;
}

__attribute__((noinline, used)) void
port_audio1_init_pitch_slide_vars(struct audio_init_pitch_slide_state *state)
{
	audio_init_pitch_slide_vars(state);
}

void port_audio2_init_pitch_slide_vars(struct audio_init_pitch_slide_state *state)
	__attribute__((alias("port_audio1_init_pitch_slide_vars"), used));

void port_audio3_init_pitch_slide_vars(struct audio_init_pitch_slide_state *state)
	__attribute__((alias("port_audio1_init_pitch_slide_vars"), used));

static void
audio_execute_music(struct audio_execute_music_state *state)
{
	state->registers.f = audio_cp_flags(state->registers.a, 0xf8);
	if (state->registers.a != 0xf8) {
		state->continuation = AUDIO_CONTINUE_OCTAVE;
		return;
	}

	state->registers.b = 0;
	state->flags2[state->registers.c] |= 1;
	state->registers.f = PORT_FLAG_Z;
	state->registers.h = 0xc0;
	state->registers.l = 0x36 + state->registers.c;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_execute_music(struct audio_execute_music_state *state)
{
	audio_execute_music(state);
}

__attribute__((noinline, used)) void
port_audio2_execute_music(struct audio_execute_music_state *state)
{
	audio_execute_music(state);
}

__attribute__((noinline, used)) void
port_audio3_execute_music(struct audio_execute_music_state *state)
{
	audio_execute_music(state);
}

static void
audio_octave(struct audio_octave_state *state)
{
	state->registers.a &= 0xf0;
	state->registers.f = audio_cp_flags(state->registers.a, 0xe0);
	if (state->registers.a != 0xe0) {
		state->continuation = AUDIO_CONTINUE_SFX_NOTE;
		return;
	}

	state->registers.b = 0;
	state->registers.a = state->registers.d & 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->octaves[state->registers.c] = state->registers.a;
	state->registers.h = 0xc0;
	state->registers.l = 0xd6 + state->registers.c;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_octave(struct audio_octave_state *state)
{
	audio_octave(state);
}

__attribute__((noinline, used)) void
port_audio2_octave(struct audio_octave_state *state)
{
	audio_octave(state);
}

__attribute__((noinline, used)) void
port_audio3_octave(struct audio_octave_state *state)
{
	audio_octave(state);
}

static void
audio_fetch_command_byte(
	struct cpu_register_state *registers,
	port_u8 command_pointers[16],
	port_u8 command_byte)
{
	port_u8 offset = registers->c * 2;
	port_u16 pointer = command_pointers[offset] |
		((port_u16)command_pointers[offset + 1] << 8);

	registers->f = registers->c == 0 ? PORT_FLAG_Z : 0;
	registers->a = command_byte;
	pointer++;
	registers->d = (port_u8)(pointer >> 8);
	registers->e = (port_u8)pointer;
	command_pointers[offset] = registers->e;
	command_pointers[offset + 1] = registers->d;
	registers->h = 0xc0;
	registers->l = 0x07 + offset;
}

static void
audio_duty_cycle_command(struct audio_duty_cycle_command_state *state)
{
	port_u8 result;

	state->registers.f = audio_cp_flags(state->registers.a, 0xec);
	if (state->registers.a != 0xec) {
		state->continuation = AUDIO_CONTINUE_TEMPO;
		return;
	}

	audio_fetch_command_byte(
		&state->registers, state->command_pointers, state->command_byte);
	result = (port_u8)((state->registers.a >> 2) |
		(state->registers.a << 6)) & 0xc0;
	state->registers.a = result;
	state->registers.f = result == 0 ? PORT_FLAG_Z : 0;
	state->registers.b = 0;
	state->duty_cycles[state->registers.c] = result;
	state->registers.h = 0xc0;
	state->registers.l = 0x3e + state->registers.c;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_duty_cycle(struct audio_duty_cycle_command_state *state)
{
	audio_duty_cycle_command(state);
}

__attribute__((noinline, used)) void
port_audio2_duty_cycle(struct audio_duty_cycle_command_state *state)
{
	audio_duty_cycle_command(state);
}

__attribute__((noinline, used)) void
port_audio3_duty_cycle(struct audio_duty_cycle_command_state *state)
{
	audio_duty_cycle_command(state);
}

static void
audio_byte_command(
	struct audio_byte_command_state *state,
	port_u8 expected_command,
	port_u8 fallthrough_continuation)
{
	state->registers.f = audio_cp_flags(state->registers.a, expected_command);
	if (state->registers.a != expected_command) {
		state->continuation = fallthrough_continuation;
		return;
	}

	audio_fetch_command_byte(
		&state->registers, state->command_pointers, state->command_byte);
	state->value = state->registers.a;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_stereo_panning(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xee, AUDIO_CONTINUE_UNKNOWN_EF);
}

__attribute__((noinline, used)) void
port_audio2_stereo_panning(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xee, AUDIO_CONTINUE_UNKNOWN_EF);
}

__attribute__((noinline, used)) void
port_audio3_stereo_panning(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xee, AUDIO_CONTINUE_UNKNOWN_EF);
}

__attribute__((noinline, used)) void
port_audio1_volume(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xf0, AUDIO_CONTINUE_EXECUTE_MUSIC);
}

__attribute__((noinline, used)) void
port_audio2_volume(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xf0, AUDIO_CONTINUE_EXECUTE_MUSIC);
}

__attribute__((noinline, used)) void
port_audio3_volume(struct audio_byte_command_state *state)
{
	audio_byte_command(state, 0xf0, AUDIO_CONTINUE_EXECUTE_MUSIC);
}

static void
audio_duty_cycle_pattern_command(struct audio_duty_pattern_command_state *state)
{
	port_u8 channel;
	port_u8 pattern;

	state->registers.f = audio_cp_flags(state->registers.a, 0xfc);
	if (state->registers.a != 0xfc) {
		state->continuation = AUDIO_CONTINUE_VOLUME;
		return;
	}

	audio_fetch_command_byte(
		&state->registers, state->command_pointers, state->command_byte);
	channel = state->registers.c;
	pattern = state->registers.a;
	state->registers.b = 0;
	state->duty_patterns[channel] = pattern;
	state->registers.a = pattern & 0xc0;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->duty_cycles[channel] = state->registers.a;
	state->flags1[channel] |= 0x40;
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_duty_cycle_pattern(struct audio_duty_pattern_command_state *state)
{
	audio_duty_cycle_pattern_command(state);
}

__attribute__((noinline, used)) void
port_audio2_duty_cycle_pattern(struct audio_duty_pattern_command_state *state)
{
	audio_duty_cycle_pattern_command(state);
}

__attribute__((noinline, used)) void
port_audio3_duty_cycle_pattern(struct audio_duty_pattern_command_state *state)
{
	audio_duty_cycle_pattern_command(state);
}

static void
audio_tempo_command(struct audio_tempo_command_state *state)
{
	port_u8 channel;

	state->registers.f = audio_cp_flags(state->registers.a, 0xed);
	if (state->registers.a != 0xed) {
		state->continuation = AUDIO_CONTINUE_STEREO_PANNING;
		return;
	}

	channel = state->registers.c;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 4);
	if (channel < 4) {
		audio_fetch_command_byte(
			&state->registers,
			state->command_pointers,
			state->command_bytes[0]);
		state->music_tempo[0] = state->registers.a;
		audio_fetch_command_byte(
			&state->registers,
			state->command_pointers,
			state->command_bytes[1]);
		state->music_tempo[1] = state->registers.a;
		state->fractional_note_delays[0] = 0;
		state->fractional_note_delays[1] = 0;
		state->fractional_note_delays[2] = 0;
		state->fractional_note_delays[3] = 0;
	} else {
		audio_fetch_command_byte(
			&state->registers,
			state->command_pointers,
			state->command_bytes[0]);
		state->sfx_tempo[0] = state->registers.a;
		audio_fetch_command_byte(
			&state->registers,
			state->command_pointers,
			state->command_bytes[1]);
		state->sfx_tempo[1] = state->registers.a;
		state->fractional_note_delays[4] = 0;
		state->fractional_note_delays[5] = 0;
		state->fractional_note_delays[6] = 0;
		state->fractional_note_delays[7] = 0;
	}
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_tempo(struct audio_tempo_command_state *state)
{
	audio_tempo_command(state);
}

__attribute__((noinline, used)) void
port_audio2_tempo(struct audio_tempo_command_state *state)
{
	audio_tempo_command(state);
}

__attribute__((noinline, used)) void
port_audio3_tempo(struct audio_tempo_command_state *state)
{
	audio_tempo_command(state);
}

static void
audio_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *state)
{
	port_u8 channel;

	state->registers.a = state->registers.d;
	state->registers.f = audio_cp_flags(state->registers.a, 0xe8);
	if (state->registers.a != 0xe8) {
		state->continuation = AUDIO_CONTINUE_VIBRATO;
		return;
	}

	channel = state->registers.c;
	state->registers.b = 0;
	state->registers.a = state->flags1[channel] ^ 1;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->flags1[channel] = state->registers.a;
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *state)
{
	audio_toggle_perfect_pitch(state);
}

__attribute__((noinline, used)) void
port_audio2_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *state)
{
	audio_toggle_perfect_pitch(state);
}

__attribute__((noinline, used)) void
port_audio3_toggle_perfect_pitch(struct audio_toggle_perfect_pitch_state *state)
{
	audio_toggle_perfect_pitch(state);
}

static void
audio_vibrato_command(struct audio_vibrato_command_state *state)
{
	port_u8 channel;
	port_u8 parameter;
	port_u8 extent;
	port_u8 extent_below;
	port_u8 extent_above;
	port_u8 rate;

	state->registers.f = audio_cp_flags(state->registers.a, 0xea);
	if (state->registers.a != 0xea) {
		state->continuation = AUDIO_CONTINUE_PITCH_SLIDE;
		return;
	}

	channel = state->registers.c;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[0]);
	state->registers.b = 0;
	state->delay_counters[channel] = state->registers.a;
	state->delay_reloads[channel] = state->registers.a;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[1]);
	parameter = state->registers.a;
	state->registers.d = parameter;
	extent = parameter >> 4;
	extent_below = extent >> 1;
	extent_above = extent_below + (extent & 1);
	state->registers.b = 0;
	state->registers.e = extent_below;
	state->registers.a = (port_u8)((extent_above << 4) | extent_below);
	state->extents[channel] = state->registers.a;
	rate = parameter & 0x0f;
	state->registers.d = rate;
	state->registers.a = (port_u8)((rate << 4) | rate);
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->rates[channel] = state->registers.a;
	state->registers.h = 0xc0;
	state->registers.l = 0x5e + channel;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_vibrato(struct audio_vibrato_command_state *state)
{
	audio_vibrato_command(state);
}

__attribute__((noinline, used)) void
port_audio2_vibrato(struct audio_vibrato_command_state *state)
{
	audio_vibrato_command(state);
}

__attribute__((noinline, used)) void
port_audio3_vibrato(struct audio_vibrato_command_state *state)
{
	audio_vibrato_command(state);
}

static void
audio_pitch_sweep(struct audio_pitch_sweep_state *state)
{
	port_u8 channel = state->registers.c;

	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 4);
	if (channel < 4) {
		state->continuation = AUDIO_CONTINUE_NOTE;
		return;
	}

	state->registers.a = state->registers.d;
	state->registers.f = audio_cp_flags(state->registers.a, 0x10);
	if (state->registers.a != 0x10) {
		state->continuation = AUDIO_CONTINUE_NOTE;
		return;
	}

	state->registers.b = 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x36 + channel;
	state->registers.f = PORT_FLAG_H;
	if ((state->flags2[channel] & 1) == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((state->flags2[channel] & 1) != 0) {
		state->continuation = AUDIO_CONTINUE_NOTE;
		return;
	}

	audio_fetch_command_byte(
		&state->registers, state->command_pointers, state->command_byte);
	state->sweep = state->registers.a;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_pitch_sweep(struct audio_pitch_sweep_state *state)
{
	audio_pitch_sweep(state);
}

__attribute__((noinline, used)) void
port_audio2_pitch_sweep(struct audio_pitch_sweep_state *state)
{
	audio_pitch_sweep(state);
}

__attribute__((noinline, used)) void
port_audio3_pitch_sweep(struct audio_pitch_sweep_state *state)
{
	audio_pitch_sweep(state);
}

static void
audio_pitch_slide_command(
	struct audio_pitch_slide_command_state *state,
	port_u16 pitches_address)
{
	port_u8 channel;
	port_u8 parameter;

	state->registers.f = audio_cp_flags(state->registers.a, 0xeb);
	if (state->registers.a != 0xeb) {
		state->continuation = AUDIO_CONTINUE_DUTY_CYCLE;
		return;
	}

	channel = state->registers.c;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[0]);
	state->registers.b = 0;
	state->length_modifiers[channel] = state->registers.a;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[1]);
	parameter = state->registers.a;
	state->registers.d = parameter;
	state->registers.a = parameter >> 4;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.b = state->registers.a;
	state->registers.a = parameter & 0x0f;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
	audio_calculate_frequency(&state->registers, pitches_address);
	state->registers.b = 0;
	state->target_frequency_high[channel] = state->registers.d;
	state->target_frequency_low[channel] = state->registers.e;
	state->flags1[channel] |= 0x10;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[2]);
	state->registers.d = state->registers.a;
	state->continuation = AUDIO_CONTINUE_NOTE_LENGTH;
}

__attribute__((noinline, used)) void
port_audio1_pitch_slide(struct audio_pitch_slide_command_state *state)
{
	audio_pitch_slide_command(state, 0x5b2f);
}

__attribute__((noinline, used)) void
port_audio2_pitch_slide(struct audio_pitch_slide_command_state *state)
{
	audio_pitch_slide_command(state, 0x62ee);
}

__attribute__((noinline, used)) void
port_audio3_pitch_slide(struct audio_pitch_slide_command_state *state)
{
	audio_pitch_slide_command(state, 0x5ba3);
}

static void
audio_note_type(struct audio_note_type_state *state)
{
	port_u8 channel;
	port_u8 parameter;
	port_u8 volume;

	state->registers.a &= 0xf0;
	state->registers.f = audio_cp_flags(state->registers.a, 0xd0);
	if (state->registers.a != 0xd0) {
		state->continuation = AUDIO_CONTINUE_TOGGLE_PERFECT_PITCH;
		return;
	}

	channel = state->registers.c;
	state->registers.a = state->registers.d & 0x0f;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
	state->registers.b = 0;
	state->note_speeds[channel] = state->registers.a;
	state->registers.h = 0xc0;
	state->registers.l = 0xc6 + channel;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 3);
	if (channel == 3) {
		state->continuation = AUDIO_CONTINUE_SOUND_RET;
		return;
	}

	audio_fetch_command_byte(
		&state->registers, state->command_pointers, state->command_byte);
	parameter = state->registers.a;
	state->registers.d = parameter;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 2);
	if (channel == 2 || channel == 6) {
		if (channel == 6)
			state->registers.f = audio_cp_flags(channel, 6);
		state->registers.a = parameter & 0x0f;
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
		if (channel == 2) {
			state->music_wave_instrument = state->registers.a;
			state->registers.h = 0xc0;
			state->registers.l = 0xe6;
		} else {
			state->sfx_wave_instrument = state->registers.a;
			state->registers.h = 0xc0;
			state->registers.l = 0xe7;
		}
		volume = (port_u8)((parameter & 0x30) << 1);
		state->registers.a = volume;
		state->registers.d = volume;
		state->registers.f = volume == 0 ? PORT_FLAG_Z : 0;
	} else {
		state->registers.f = audio_cp_flags(channel, 6);
	}
	state->registers.b = 0;
	state->volumes[channel] = state->registers.d;
	state->registers.h = 0xc0;
	state->registers.l = 0xde + channel;
	state->registers.f &= PORT_FLAG_Z;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_note_type(struct audio_note_type_state *state)
{
	audio_note_type(state);
}

__attribute__((noinline, used)) void
port_audio2_note_type(struct audio_note_type_state *state)
{
	audio_note_type(state);
}

__attribute__((noinline, used)) void
port_audio3_note_type(struct audio_note_type_state *state)
{
	audio_note_type(state);
}

static void
audio_sound_call(struct audio_sound_call_state *state)
{
	port_u8 channel;
	port_u8 offset;
	port_u16 current_pointer;

	state->registers.f = audio_cp_flags(state->registers.a, 0xfd);
	if (state->registers.a != 0xfd) {
		state->continuation = AUDIO_CONTINUE_SOUND_LOOP;
		return;
	}

	channel = state->registers.c;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[0]);
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[1]);
	offset = channel * 2;
	current_pointer = state->command_pointers[offset] |
		((port_u16)state->command_pointers[offset + 1] << 8);
	state->return_addresses[offset] = (port_u8)current_pointer;
	state->return_addresses[offset + 1] = (port_u8)(current_pointer >> 8);
	state->command_pointers[offset] = state->command_bytes[0];
	state->command_pointers[offset + 1] = state->command_bytes[1];
	state->registers.a = (port_u8)(current_pointer >> 8);
	state->registers.b = 0;
	state->registers.d = state->command_bytes[1];
	state->registers.e = state->command_bytes[0];
	state->registers.f = channel == 0 ? PORT_FLAG_Z : 0;
	state->flags1[channel] |= 0x02;
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_sound_call(struct audio_sound_call_state *state)
{
	audio_sound_call(state);
}

__attribute__((noinline, used)) void
port_audio2_sound_call(struct audio_sound_call_state *state)
{
	audio_sound_call(state);
}

__attribute__((noinline, used)) void
port_audio3_sound_call(struct audio_sound_call_state *state)
{
	audio_sound_call(state);
}

static void
audio_sound_loop(struct audio_sound_loop_state *state)
{
	port_u8 channel;
	port_u8 offset;
	port_u8 count;
	port_u8 target_low;
	port_u8 target_high;

	state->registers.f = audio_cp_flags(state->registers.a, 0xfe);
	if (state->registers.a != 0xfe) {
		state->continuation = AUDIO_CONTINUE_NOTE_TYPE;
		return;
	}

	channel = state->registers.c;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[0]);
	count = state->registers.a;
	state->registers.e = count;
	if (count != 0) {
		state->registers.b = 0;
		state->registers.a = state->loop_counters[channel];
		state->registers.f = audio_cp_flags(state->registers.a, count);
		if (state->registers.a == count) {
			state->registers.a = 1;
			state->loop_counters[channel] = 1;
			audio_fetch_command_byte(
				&state->registers,
				state->command_pointers,
				state->command_bytes[1]);
			audio_fetch_command_byte(
				&state->registers,
				state->command_pointers,
				state->command_bytes[2]);
			state->continuation = AUDIO_CONTINUE_SOUND_RET;
			return;
		}
		state->registers.a++;
		state->loop_counters[channel] = state->registers.a;
	}

	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[1]);
	target_low = state->registers.a;
	audio_fetch_command_byte(
		&state->registers,
		state->command_pointers,
		state->command_bytes[2]);
	target_high = state->registers.a;
	offset = channel * 2;
	state->command_pointers[offset] = target_low;
	state->command_pointers[offset + 1] = target_high;
	state->registers.a = target_low;
	state->registers.b = target_high;
	state->registers.d = 0;
	state->registers.e = offset;
	state->registers.f = channel == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_sound_loop(struct audio_sound_loop_state *state)
{
	audio_sound_loop(state);
}

__attribute__((noinline, used)) void
port_audio2_sound_loop(struct audio_sound_loop_state *state)
{
	audio_sound_loop(state);
}

__attribute__((noinline, used)) void
port_audio3_sound_loop(struct audio_sound_loop_state *state)
{
	audio_sound_loop(state);
}

static port_u8
audio_note_length_uses_modified_sfx_tempo(
	const struct audio_note_length_state *state,
	port_u8 variant)
{
	port_u8 sound5 = state->channel5_sound_id;

	if (sound5 >= 0x14 && sound5 < 0x86)
		return 1;
	if (variant == 2) {
		port_u8 combined = sound5 | state->channel8_sound_id;
		return combined >= 0x9d && combined < 0xea;
	}
	return 0;
}

__attribute__((noinline, used)) port_u16
port_audio_note_delay_arithmetic(
	port_u8 factor, port_u16 tempo, port_u8 fractional)
{
	return (port_u16)(fractional + (port_u16)factor * tempo);
}

static void
audio_note_length(struct audio_note_length_state *state, port_u8 variant)
{
	port_u8 channel = state->registers.c;
	port_u8 length = (state->registers.d & 0x0f) + 1;
	port_u16 first_product = (port_u16)length * state->note_speeds[channel];
	port_u16 tempo;
	port_u16 delay;

	state->saved_a = state->registers.d;
	state->saved_f = state->registers.f;
	if (channel < 4) {
		tempo = ((port_u16)state->music_tempo[0] << 8) |
			state->music_tempo[1];
	} else if (channel == 7) {
		tempo = 0x0100;
	} else {
		if (audio_note_length_uses_modified_sfx_tempo(state, variant)) {
			port_u16 adjusted = (port_u16)state->tempo_modifier + 0x80;
			state->sfx_tempo[0] = (port_u8)(adjusted >> 8);
			state->sfx_tempo[1] = (port_u8)adjusted;
		} else {
			state->sfx_tempo[0] = 1;
			state->sfx_tempo[1] = 0;
		}
		tempo = ((port_u16)state->sfx_tempo[0] << 8) |
			state->sfx_tempo[1];
	}

	delay = port_audio_note_delay_arithmetic(
		(port_u8)first_product,
		tempo,
		state->fractional_note_delays[channel]);
	state->fractional_note_delays[channel] = (port_u8)delay;
	state->note_delays[channel] = (port_u8)(delay >> 8);
	state->registers.a = (port_u8)(delay >> 8);
	state->registers.b = 0;
	state->registers.d = state->registers.a;
	state->registers.e = (port_u8)delay;
	if (state->flags2[channel] & 1) {
		state->registers.f = PORT_FLAG_H;
		state->registers.h = 0xc0;
		state->registers.l = 0x36 + channel;
		state->continuation = AUDIO_CONTINUE_NOTE_PITCH;
		return;
	}
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	if ((state->flags1[channel] & 4) == 0) {
		state->registers.f = PORT_FLAG_Z | PORT_FLAG_H;
		state->continuation = AUDIO_CONTINUE_NOTE_PITCH;
		return;
	}
	state->registers.f = PORT_FLAG_H;
	state->registers.h = state->saved_a;
	state->registers.l = state->saved_f;
	state->continuation = AUDIO_CONTINUE_RETURN;
}

__attribute__((noinline, used)) void
port_audio1_note_length(struct audio_note_length_state *state)
{
	audio_note_length(state, 1);
}

__attribute__((noinline, used)) void
port_audio2_note_length(struct audio_note_length_state *state)
{
	audio_note_length(state, 2);
}

__attribute__((noinline, used)) void
port_audio3_note_length(struct audio_note_length_state *state)
{
	audio_note_length(state, 3);
}

static port_u8
audio_bit_flags(port_u8 old_flags, port_u8 value, port_u8 mask)
{
	return (old_flags & PORT_FLAG_C) | PORT_FLAG_H |
		((value & mask) == 0 ? PORT_FLAG_Z : 0);
}

static void
audio_note_pitch(
	struct audio_note_pitch_state *state,
	port_u8 variant,
	port_u16 pitches_address,
	port_u16 enable_masks_address,
	port_u16 disable_masks_address)
{
	static const port_u8 disable_masks[8] = {
		0xee, 0xdd, 0xbb, 0x77, 0xee, 0xdd, 0xbb, 0x77,
	};
	port_u8 channel = state->registers.c;
	port_u8 hardware_channel = channel & 3;
	port_u8 note;
	port_u8 i;
	port_u8 frequency_high;
	port_u8 frequency_low;

	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	state->registers.a &= 0xf0;
	state->registers.f = state->registers.a == 0 ?
		PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
	state->registers.f = audio_cp_flags(state->registers.a, 0xc0);
	if (state->registers.a == 0xc0) {
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, 4);
		if (channel < 4) {
			state->registers.h = 0xc0;
			state->registers.l = 0x2a + channel;
			state->registers.a = state->sfx_sound_ids[channel];
			state->registers.f = state->registers.a == 0 ?
				PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
			if (state->registers.a != 0)
				return;
		}
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, 2);
		if (channel == 2 || channel == 6) {
			state->registers.b = 0;
			state->registers.h = (port_u8)(disable_masks_address >> 8);
			state->registers.l =
				(port_u8)(disable_masks_address + channel);
			state->registers.a = state->audio_terminal & disable_masks[channel];
			state->registers.f = state->registers.a == 0 ?
				PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
			state->audio_terminal = state->registers.a;
			return;
		}
		state->registers.b = 2;
		audio_get_register_pointer(&state->registers);
		state->hardware_volume_envelopes[hardware_channel] = 8;
		state->registers.a = 8;
		state->registers.l += 2;
		state->registers.a = 0x80;
		state->hardware_frequency_registers[hardware_channel * 2 + 1] = 0x80;
		return;
	}

	note = (port_u8)((state->registers.a << 4) |
		(state->registers.a >> 4));
	state->registers.a = note;
	state->registers.f = note == 0 ? PORT_FLAG_Z : 0;
	state->registers.b = state->octaves[channel];
	audio_calculate_frequency(&state->registers, pitches_address);
	state->registers.b = 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags1[channel], 0x10);
	if (state->flags1[channel] & 0x10) {
		struct audio_init_pitch_slide_state slide;
		slide.registers = state->registers;
		for (i = 0; i != 8; i++) {
			slide.flags1[i] = state->flags1[i];
			slide.note_delays[i] = state->note_delays[i];
			slide.length_modifiers[i] = state->length_modifiers[i];
			slide.frequency_steps[i] = state->frequency_steps[i];
			slide.frequency_steps_fractional[i] =
				state->frequency_steps_fractional[i];
			slide.current_frequency_fractional[i] =
				state->current_frequency_fractional[i];
			slide.current_frequency_high[i] = state->current_frequency_high[i];
			slide.current_frequency_low[i] = state->current_frequency_low[i];
			slide.target_frequency_high[i] = state->target_frequency_high[i];
			slide.target_frequency_low[i] = state->target_frequency_low[i];
		}
		port_audio1_init_pitch_slide_vars(&slide);
		state->registers = slide.registers;
		for (i = 0; i != 8; i++) {
			state->flags1[i] = slide.flags1[i];
			state->length_modifiers[i] = slide.length_modifiers[i];
			state->frequency_steps[i] = slide.frequency_steps[i];
			state->frequency_steps_fractional[i] =
				slide.frequency_steps_fractional[i];
			state->current_frequency_fractional[i] =
				slide.current_frequency_fractional[i];
			state->current_frequency_high[i] = slide.current_frequency_high[i];
			state->current_frequency_low[i] = slide.current_frequency_low[i];
		}
	}
	frequency_high = state->registers.d;
	frequency_low = state->registers.e;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 4);
	if (channel < 4) {
		state->registers.h = 0xc0;
		state->registers.l = 0x2a + channel;
		state->registers.d = 0;
		state->registers.e = channel;
		state->registers.a = state->sfx_sound_ids[channel];
		state->registers.f = state->registers.a == 0 ?
			PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
		if (state->registers.a != 0) {
			state->registers.d = frequency_high;
			state->registers.e = frequency_low;
			return;
		}
	}

	state->registers.b = 2;
	state->registers.d = state->volumes[channel];
	audio_get_register_pointer(&state->registers);
	state->hardware_volume_envelopes[hardware_channel] = state->registers.d;
	{
		struct audio_duty_length_state duty;
		duty.registers = state->registers;
		for (i = 0; i != 8; i++) {
			duty.note_delays[i] = state->note_delays[i];
			duty.duty_cycles[i] = state->duty_cycles[i];
		}
		for (i = 0; i != 4; i++)
			duty.hardware_duty_registers[i] = state->hardware_duty_registers[i];
		audio_apply_duty_cycle_and_sound_length(&duty);
		state->registers = duty.registers;
		for (i = 0; i != 4; i++)
			state->hardware_duty_registers[i] = duty.hardware_duty_registers[i];
	}
	{
		struct audio_channel_output_state output;
		output.registers = state->registers;
		for (i = 0; i != 4; i++)
			output.sfx_sound_ids[i] = state->sfx_sound_ids[i];
		output.stereo_panning = state->stereo_panning;
		output.audio_terminal = state->audio_terminal;
		audio_enable_channel_output(
			&output, enable_masks_address, disable_masks_address);
		state->registers = output.registers;
		state->audio_terminal = output.audio_terminal;
	}
	state->registers.d = frequency_high;
	state->registers.e = frequency_low;
	state->registers.b = 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x2e + channel;
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags1[channel], 1);
	if (state->flags1[channel] & 1) {
		state->registers.e++;
		if (state->registers.f & PORT_FLAG_C)
			state->registers.d++;
	}
	state->frequency_low_bytes[channel] = state->registers.e;
	{
		struct audio_wave_frequency_state wave;
		wave.registers = state->registers;
		wave.music_wave_instrument = state->music_wave_instrument;
		wave.sfx_wave_instrument = state->sfx_wave_instrument;
		wave.channel5_sound_id = state->channel5_sound_id;
		wave.channel8_sound_id = state->channel8_sound_id;
		wave.frequency_modifier = state->frequency_modifier;
		wave.audio3_enable = state->audio3_enable;
		for (i = 0; i != 16; i++)
			wave.wave_ram[i] = state->wave_ram[i];
		for (i = 0; i != 8; i++)
			wave.hardware_frequency_registers[i] =
				state->hardware_frequency_registers[i];
		audio_apply_wave_pattern_and_frequency(&wave, variant - 1);
		state->registers = wave.registers;
		state->audio3_enable = wave.audio3_enable;
		for (i = 0; i != 16; i++)
			state->wave_ram[i] = wave.wave_ram[i];
		for (i = 0; i != 8; i++)
			state->hardware_frequency_registers[i] =
				wave.hardware_frequency_registers[i];
	}
}

__attribute__((noinline, used)) void
port_audio1_note_pitch(struct audio_note_pitch_state *state)
{
	audio_note_pitch(state, 1, 0x5b2f, 0x5b27, 0x5b1f);
}

__attribute__((noinline, used)) void
port_audio2_note_pitch(struct audio_note_pitch_state *state)
{
	audio_note_pitch(state, 2, 0x62ee, 0x62e6, 0x62de);
}

__attribute__((noinline, used)) void
port_audio3_note_pitch(struct audio_note_pitch_state *state)
{
	audio_note_pitch(state, 3, 0x5ba3, 0x5b9b, 0x5b93);
}

static void
audio_play_next_note(struct audio_play_next_note_state *state, port_u8 variant)
{
	port_u8 channel = state->registers.c;

	state->registers.h = 0xc0;
	state->registers.l = 0x6e + channel;
	state->registers.a = state->vibrato_delay_reloads[channel];
	state->registers.l = 0x4e + channel;
	state->vibrato_delay_counters[channel] = state->registers.a;
	state->registers.l = 0x2e + channel;
	state->flags1[channel] &= (port_u8)~0x30;
	state->registers.f &= PORT_FLAG_Z;
	if (variant == 2) {
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, 4);
		if (channel == 4) {
			state->registers.a = state->low_health_alarm;
			state->registers.f = audio_bit_flags(
				state->registers.f, state->registers.a, 0x80);
			if (state->registers.a & 0x80) {
				state->continuation = AUDIO_CONTINUE_RETURN;
				return;
			}
		}
	}
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_play_next_note(struct audio_play_next_note_state *state)
{
	audio_play_next_note(state, 1);
}

__attribute__((noinline, used)) void
port_audio2_play_next_note(struct audio_play_next_note_state *state)
{
	audio_play_next_note(state, 2);
}

__attribute__((noinline, used)) void
port_audio3_play_next_note(struct audio_play_next_note_state *state)
{
	audio_play_next_note(state, 3);
}

static void
audio_sound_ret_get_byte(
	struct audio_sound_ret_state *state, port_u8 command_index)
{
	struct audio_next_music_byte_state next;
	port_u8 i;

	next.registers = state->registers;
	for (i = 0; i != 16; i++)
		next.command_pointers[i] = state->command_pointers[i];
	next.command_byte = state->command_bytes[command_index];
	audio_get_next_music_byte(&next);
	state->registers = next.registers;
	for (i = 0; i != 16; i++)
		state->command_pointers[i] = next.command_pointers[i];
}

static void
audio_sound_ret(
	struct audio_sound_ret_state *state,
	port_u16 disable_masks_address)
{
	static const port_u8 disable_masks[8] = {
		0xee, 0xdd, 0xbb, 0x77, 0xee, 0xdd, 0xbb, 0x77,
	};
	port_u8 channel = state->registers.c;
	port_u8 offset = channel * 2;
	port_u8 command_index = 0;

	for (;;) {
		audio_sound_ret_get_byte(state, command_index++);
		state->registers.d = state->registers.a;
		state->registers.f = audio_cp_flags(state->registers.a, 0xff);
		if (state->registers.a != 0xff) {
			state->continuation = AUDIO_CONTINUE_SOUND_CALL;
			return;
		}

		state->registers.b = 0;
		state->registers.h = 0xc0;
		state->registers.l = 0x2e + channel;
		state->registers.f = audio_bit_flags(
			state->registers.f, state->flags1[channel], 2);
		if ((state->flags1[channel] & 2) == 0)
			break;

		state->flags1[channel] &= (port_u8)~2;
		state->registers.d = 0;
		state->registers.a = channel;
		state->registers.f = audio_add_flags(channel, channel);
		state->registers.e = channel * 2;
		state->registers.h = 0xc0;
		state->registers.l = 0x07 + offset;
		state->command_pointers[offset] = state->return_addresses[offset];
		state->command_pointers[offset + 1] = state->return_addresses[offset + 1];
		state->registers.a = state->return_addresses[offset + 1];
	}

	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 3);
	if (channel >= 3) {
		state->flags1[channel] &= (port_u8)~4;
		state->registers.h = 0xc0;
		state->registers.l = 0x36 + channel;
		state->flags2[channel] &= (port_u8)~1;
		state->registers.f = audio_cp_flags(channel, 6);
		if (channel == 6) {
			state->registers.a = 0;
			state->audio3_enable = 0;
			state->registers.a = 0x80;
			state->audio3_enable = 0x80;
			if (state->disable_channel_output != 0) {
				state->registers.a = 0;
				state->registers.f = PORT_FLAG_Z;
				state->disable_channel_output = 0;
				goto disable_output;
			}
		}
		goto after_disable;
	}

disable_output:
	state->registers.h = (port_u8)(disable_masks_address >> 8);
	state->registers.l = (port_u8)(disable_masks_address + channel);
	state->registers.a = state->audio_terminal & disable_masks[channel];
	state->registers.f = state->registers.a == 0 ?
		PORT_FLAG_Z | PORT_FLAG_H : PORT_FLAG_H;
	state->audio_terminal = state->registers.a;

after_disable:
	state->registers.a = state->sound_ids[4];
	state->registers.f = audio_cp_flags(state->registers.a, 0x14);
	if (state->registers.a >= 0x14) {
		state->registers.f = audio_cp_flags(state->registers.a, 0x86);
		if (state->registers.a < 0x86) {
			state->registers.a = channel;
			state->registers.f = audio_cp_flags(channel, 4);
			if (channel != 4) {
				port_u16 pointer = state->command_pointers[offset] |
					((port_u16)state->command_pointers[offset + 1] << 8);
				pointer--;
				state->command_pointers[offset] = (port_u8)pointer;
				state->command_pointers[offset + 1] = (port_u8)(pointer >> 8);
				state->registers.a = (port_u8)(pointer >> 8);
				state->registers.f = PORT_FLAG_C |
					(state->registers.a == 0 ? PORT_FLAG_Z : 0);
				state->registers.d = 0;
				state->registers.e = offset;
				state->registers.h = 0xc0;
				state->registers.l = 0x07 + offset;
				state->continuation = AUDIO_CONTINUE_RETURN;
				return;
			}
			state->registers.a = state->saved_volume;
			state->audio_volume = state->registers.a;
			state->registers.a = 0;
			state->registers.f = PORT_FLAG_Z;
			state->saved_volume = 0;
		}
	}
	state->registers.h = 0xc0;
	state->registers.l = 0x26 + channel;
	state->registers.f &= PORT_FLAG_Z;
	state->sound_ids[channel] = state->registers.b;
	state->continuation = AUDIO_CONTINUE_RETURN;
}

__attribute__((noinline, used)) void
port_audio1_sound_ret(struct audio_sound_ret_state *state)
{
	audio_sound_ret(state, 0x5b1f);
}

__attribute__((noinline, used)) void
port_audio2_sound_ret(struct audio_sound_ret_state *state)
{
	audio_sound_ret(state, 0x62de);
}

__attribute__((noinline, used)) void
port_audio3_sound_ret(struct audio_sound_ret_state *state)
{
	audio_sound_ret(state, 0x5b93);
}

static void
audio_sfx_note_get_byte(struct audio_sfx_note_state *state, port_u8 index)
{
	port_u8 offset = state->registers.c * 2;
	port_u16 pointer = state->command_pointers[offset] |
		((port_u16)state->command_pointers[offset + 1] << 8);

	state->registers.f = state->registers.c == 0 ? PORT_FLAG_Z : 0;
	state->registers.a = state->command_bytes[index];
	pointer++;
	state->registers.d = (port_u8)(pointer >> 8);
	state->registers.e = (port_u8)pointer;
	state->command_pointers[offset] = state->registers.e;
	state->command_pointers[offset + 1] = state->registers.d;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
}

static void
audio_sfx_note_length(struct audio_sfx_note_state *state, port_u8 variant)
{
	struct audio_note_length_state length;
	port_u8 i;

	length.registers = state->registers;
	for (i = 0; i != 8; i++) {
		length.note_speeds[i] = state->note_speeds[i];
		length.fractional_note_delays[i] = state->fractional_note_delays[i];
		length.note_delays[i] = state->note_delays[i];
		length.flags2[i] = state->flags2[i];
		length.flags1[i] = state->flags1[i];
	}
	length.music_tempo[0] = state->music_tempo[0];
	length.music_tempo[1] = state->music_tempo[1];
	length.sfx_tempo[0] = state->sfx_tempo[0];
	length.sfx_tempo[1] = state->sfx_tempo[1];
	length.channel5_sound_id = state->sound_ids[4];
	length.channel8_sound_id = state->sound_ids[7];
	length.tempo_modifier = state->tempo_modifier;
	length.saved_a = 0;
	length.saved_f = 0;
	length.continuation = 0;
	if (variant == 1)
		port_audio1_note_length(&length);
	else if (variant == 2)
		port_audio2_note_length(&length);
	else
		port_audio3_note_length(&length);
	state->registers = length.registers;
	for (i = 0; i != 8; i++) {
		state->note_speeds[i] = length.note_speeds[i];
		state->fractional_note_delays[i] = length.fractional_note_delays[i];
		state->note_delays[i] = length.note_delays[i];
		state->flags2[i] = length.flags2[i];
		state->flags1[i] = length.flags1[i];
	}
	state->music_tempo[0] = length.music_tempo[0];
	state->music_tempo[1] = length.music_tempo[1];
	state->sfx_tempo[0] = length.sfx_tempo[0];
	state->sfx_tempo[1] = length.sfx_tempo[1];
	state->sound_ids[4] = length.channel5_sound_id;
	state->sound_ids[7] = length.channel8_sound_id;
	state->tempo_modifier = length.tempo_modifier;
}

static void
audio_sfx_note(
	struct audio_sfx_note_state *state,
	port_u8 variant,
	port_u16 enable_masks_address,
	port_u16 disable_masks_address)
{
	port_u8 channel = state->registers.c;
	port_u8 hardware_channel = channel & 3;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 i;

	state->registers.f = audio_cp_flags(state->registers.a, 0x20);
	if (state->registers.a != 0x20) {
		state->continuation = AUDIO_CONTINUE_PITCH_SWEEP;
		return;
	}
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 3);
	if (channel < 3) {
		state->continuation = AUDIO_CONTINUE_PITCH_SWEEP;
		return;
	}
	state->registers.b = 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x36 + channel;
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags2[channel], 1);
	if (state->flags2[channel] & 1) {
		state->continuation = AUDIO_CONTINUE_PITCH_SWEEP;
		return;
	}

	audio_sfx_note_length(state, variant);
	state->registers.d = state->registers.a;
	state->registers.b = 0;
	state->registers.h = 0xc0;
	state->registers.l = 0x3e + channel;
	state->registers.a = state->duty_cycles[channel] | state->registers.d;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->registers.d = state->registers.a;
	state->registers.b = 1;
	audio_get_register_pointer(&state->registers);
	state->hardware_duty_registers[hardware_channel] = state->registers.d;

	audio_sfx_note_get_byte(state, 0);
	state->registers.d = state->registers.a;
	state->registers.b = 2;
	audio_get_register_pointer(&state->registers);
	state->hardware_volume_envelopes[hardware_channel] = state->registers.d;
	audio_sfx_note_get_byte(state, 1);
	state->registers.e = state->registers.a;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 7);
	state->registers.a = 0;
	if (channel != 7) {
		saved_d = state->registers.d;
		saved_e = state->registers.e;
		audio_sfx_note_get_byte(state, 2);
		state->registers.d = saved_d;
		state->registers.e = saved_e;
	}
	state->registers.d = state->registers.a;
	saved_d = state->registers.d;
	saved_e = state->registers.e;
	{
		struct audio_duty_length_state duty;
		duty.registers = state->registers;
		for (i = 0; i != 8; i++) {
			duty.note_delays[i] = state->note_delays[i];
			duty.duty_cycles[i] = state->duty_cycles[i];
		}
		for (i = 0; i != 4; i++)
			duty.hardware_duty_registers[i] = state->hardware_duty_registers[i];
		audio_apply_duty_cycle_and_sound_length(&duty);
		state->registers = duty.registers;
		for (i = 0; i != 4; i++)
			state->hardware_duty_registers[i] = duty.hardware_duty_registers[i];
	}
	{
		struct audio_channel_output_state output;
		output.registers = state->registers;
		for (i = 0; i != 4; i++)
			output.sfx_sound_ids[i] = state->sound_ids[i + 4];
		output.audio_terminal = state->audio_terminal;
		output.stereo_panning = state->stereo_panning;
		audio_enable_channel_output(
			&output, enable_masks_address, disable_masks_address);
		state->registers = output.registers;
		state->audio_terminal = output.audio_terminal;
	}
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	{
		struct audio_wave_frequency_state wave;
		wave.registers = state->registers;
		wave.music_wave_instrument = state->music_wave_instrument;
		wave.sfx_wave_instrument = state->sfx_wave_instrument;
		wave.channel5_sound_id = state->sound_ids[4];
		wave.channel8_sound_id = state->sound_ids[7];
		wave.frequency_modifier = state->frequency_modifier;
		wave.audio3_enable = state->audio3_enable;
		for (i = 0; i != 16; i++)
			wave.wave_ram[i] = state->wave_ram[i];
		for (i = 0; i != 8; i++)
			wave.hardware_frequency_registers[i] =
				state->hardware_frequency_registers[i];
		audio_apply_wave_pattern_and_frequency(&wave, variant - 1);
		state->registers = wave.registers;
		state->audio3_enable = wave.audio3_enable;
		for (i = 0; i != 16; i++)
			state->wave_ram[i] = wave.wave_ram[i];
		for (i = 0; i != 8; i++)
			state->hardware_frequency_registers[i] =
				wave.hardware_frequency_registers[i];
	}
	state->continuation = AUDIO_CONTINUE_RETURN;
}

__attribute__((noinline, used)) void
port_audio1_sfx_note(struct audio_sfx_note_state *state)
{
	audio_sfx_note(state, 1, 0x5b27, 0x5b1f);
}

__attribute__((noinline, used)) void
port_audio2_sfx_note(struct audio_sfx_note_state *state)
{
	audio_sfx_note(state, 2, 0x62e6, 0x62de);
}

__attribute__((noinline, used)) void
port_audio3_sfx_note(struct audio_sfx_note_state *state)
{
	audio_sfx_note(state, 3, 0x5b9b, 0x5b93);
}

static void
audio_apply_music_affects_set_hl(
	struct cpu_register_state *registers, port_u16 base)
{
	port_u16 left = base;
	port_u16 right = ((port_u16)registers->b << 8) | registers->c;
	port_u8 flags = registers->f & PORT_FLAG_Z;
	port_u16 result = left + right;

	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		flags |= PORT_FLAG_H;
	if (result < left)
		flags |= PORT_FLAG_C;
	registers->f = flags;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

static void
audio_apply_music_affects_return(struct audio_apply_music_affects_state *state)
{
	state->continuation = AUDIO_CONTINUE_RETURN;
}

static void
audio_apply_music_affects(struct audio_apply_music_affects_state *state)
{
	port_u8 channel = state->registers.c;
	port_u8 value;
	port_u8 result;
	port_u8 i;

	state->registers.b = 0;
	audio_apply_music_affects_set_hl(&state->registers, 0xc0b6);
	state->registers.a = state->note_delays[channel];
	state->registers.f = audio_cp_flags(state->registers.a, 1);
	if (state->registers.a == 1) {
		state->continuation = AUDIO_CONTINUE_PLAY_NEXT_NOTE;
		return;
	}
	value = state->registers.a;
	state->registers.a = value - 1;
	state->registers.f = audio_dec_flags(state->registers.f, value);
	state->note_delays[channel] = state->registers.a;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 4);
	if (channel < 4) {
		audio_apply_music_affects_set_hl(&state->registers, 0xc02a);
		state->registers.a = state->sound_ids[channel + 4];
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		else {
			audio_apply_music_affects_return(state);
			return;
		}
	}

	audio_apply_music_affects_set_hl(&state->registers, 0xc02e);
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags1[channel], 0x40);
	if (state->flags1[channel] & 0x40) {
		struct audio_duty_pattern_state duty;

		duty.registers = state->registers;
		for (i = 0; i != 8; i++)
			duty.duty_patterns[i] = state->duty_patterns[i];
		for (i = 0; i != 4; i++)
			duty.hardware_duty_registers[i] =
				state->hardware_duty_registers[i];
		audio_apply_duty_cycle_pattern(&duty);
		state->registers = duty.registers;
		for (i = 0; i != 8; i++)
			state->duty_patterns[i] = duty.duty_patterns[i];
		for (i = 0; i != 4; i++)
			state->hardware_duty_registers[i] =
				duty.hardware_duty_registers[i];
	}

	state->registers.b = 0;
	audio_apply_music_affects_set_hl(&state->registers, 0xc036);
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags2[channel], 1);
	if ((state->flags2[channel] & 1) == 0) {
		audio_apply_music_affects_set_hl(&state->registers, 0xc02e);
		state->registers.f = audio_bit_flags(
			state->registers.f, state->flags1[channel], 4);
		if (state->flags1[channel] & 4) {
			audio_apply_music_affects_return(state);
			return;
		}
	}
	audio_apply_music_affects_set_hl(&state->registers, 0xc02e);
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags1[channel], 0x10);
	if (state->flags1[channel] & 0x10) {
		state->continuation = AUDIO_CONTINUE_APPLY_PITCH_SLIDE;
		return;
	}

	audio_apply_music_affects_set_hl(&state->registers, 0xc04e);
	state->registers.a = state->vibrato_delay_counters[channel];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	else {
		value = state->vibrato_delay_counters[channel];
		state->vibrato_delay_counters[channel] = value - 1;
		state->registers.f = audio_dec_flags(state->registers.f, value);
		audio_apply_music_affects_return(state);
		return;
	}

	audio_apply_music_affects_set_hl(&state->registers, 0xc056);
	state->registers.a = state->vibrato_extents[channel];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		audio_apply_music_affects_return(state);
		return;
	}
	state->registers.d = state->registers.a;
	audio_apply_music_affects_set_hl(&state->registers, 0xc05e);
	value = state->vibrato_rates[channel];
	state->registers.a = value & 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	/* The following AND A has the same result and flags. */
	if (state->registers.a != 0) {
		state->vibrato_rates[channel] = value - 1;
		state->registers.f = audio_dec_flags(state->registers.f, value);
		audio_apply_music_affects_return(state);
		return;
	}

	state->registers.a = value;
	result = (port_u8)((value << 4) | (value >> 4));
	state->vibrato_rates[channel] = result;
	state->registers.f = result == 0 ? PORT_FLAG_Z : 0;
	state->registers.a |= result;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->vibrato_rates[channel] = state->registers.a;
	audio_apply_music_affects_set_hl(&state->registers, 0xc066);
	state->registers.e = state->frequency_low_bytes[channel];
	audio_apply_music_affects_set_hl(&state->registers, 0xc02e);
	state->registers.f = audio_bit_flags(
		state->registers.f, state->flags1[channel], 8);
	if (state->flags1[channel] & 8) {
		state->flags1[channel] &= (port_u8)~8;
		state->registers.a = state->registers.d & 0x0f;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		state->registers.d = state->registers.a;
		state->registers.a = state->registers.e;
		value = state->registers.a;
		state->registers.a -= state->registers.d;
		state->registers.f = audio_sub_flags(value, state->registers.d);
		if (state->registers.f & PORT_FLAG_C)
			state->registers.a = 0;
	} else {
		state->flags1[channel] |= 8;
		state->registers.a = state->registers.d & 0xf0;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		value = state->registers.a;
		state->registers.a = (port_u8)((value << 4) | (value >> 4));
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
		value = state->registers.a;
		state->registers.a += state->registers.e;
		state->registers.f = audio_add_flags(value, state->registers.e);
		if (state->registers.f & PORT_FLAG_C)
			state->registers.a = 0xff;
	}
	state->registers.d = state->registers.a;
	state->registers.b = 3;
	audio_get_register_pointer(&state->registers);
	state->hardware_frequency_low_registers[channel & 3] = state->registers.d;
	audio_apply_music_affects_return(state);
}

__attribute__((noinline, used)) void
port_audio1_apply_music_affects(struct audio_apply_music_affects_state *state)
{
	audio_apply_music_affects(state);
}

__attribute__((noinline, used)) void
port_audio2_apply_music_affects(struct audio_apply_music_affects_state *state)
{
	audio_apply_music_affects(state);
}

__attribute__((noinline, used)) void
port_audio3_apply_music_affects(struct audio_apply_music_affects_state *state)
{
	audio_apply_music_affects(state);
}

static void
audio_update_music(struct audio_update_music_state *state)
{
	port_u8 value;

	state->registers.c = 0;
	for (;;) {
		state->registers.b = 0;
		audio_apply_music_affects_set_hl(&state->registers, 0xc026);
		state->registers.a = state->sound_ids[state->registers.c];
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		else {
			state->registers.a = state->registers.c;
			state->registers.f = audio_cp_flags(state->registers.a, 4);
			if (state->registers.c >= 4) {
				state->continuation =
					AUDIO_CONTINUE_APPLY_MUSIC_AFFECTS;
				return;
			}
			state->registers.a = state->mute_audio_and_pause_music;
			state->registers.f = PORT_FLAG_H;
			if (state->registers.a == 0) {
				state->registers.f |= PORT_FLAG_Z;
				state->continuation =
					AUDIO_CONTINUE_APPLY_MUSIC_AFFECTS;
				return;
			}
			state->registers.f = audio_bit_flags(
				state->registers.f, state->registers.a, 0x80);
			if ((state->registers.a & 0x80) == 0) {
				state->registers.a |= 0x80;
				state->mute_audio_and_pause_music = state->registers.a;
				state->registers.a = 0;
				state->registers.f = PORT_FLAG_Z;
				state->audio_terminal = 0;
				state->audio3_enable = 0;
				state->registers.a = 0x80;
				state->audio3_enable = state->registers.a;
			}
		}
		state->registers.a = state->registers.c;
		value = state->registers.c;
		state->registers.c = value + 1;
		state->registers.f = audio_inc_flags(state->registers.f, value);
		state->registers.f = audio_cp_flags(state->registers.a, 7);
		if (state->registers.a == 7)
			break;
	}
	state->continuation = AUDIO_CONTINUE_RETURN;
}

__attribute__((noinline, used)) void
port_audio1_update_music(struct audio_update_music_state *state)
{
	audio_update_music(state);
}

__attribute__((noinline, used)) void
port_audio2_update_music(struct audio_update_music_state *state)
{
	audio_update_music(state);
}

__attribute__((noinline, used)) void
port_audio3_update_music(struct audio_update_music_state *state)
{
	audio_update_music(state);
}

enum {
	AUDIO_RAM_UNUSED = 0x00,
	AUDIO_RAM_SOUND_ID = 0x01,
	AUDIO_RAM_MUTE = 0x02,
	AUDIO_RAM_DISABLE_OUTPUT = 0x03,
	AUDIO_RAM_STEREO = 0x04,
	AUDIO_RAM_SAVED_VOLUME = 0x05,
	AUDIO_RAM_COMMAND_POINTERS = 0x06,
	AUDIO_RAM_RETURN_ADDRESSES = 0x16,
	AUDIO_RAM_SOUND_IDS = 0x26,
	AUDIO_RAM_FLAGS1 = 0x2e,
	AUDIO_RAM_FLAGS2 = 0x36,
	AUDIO_RAM_DUTY_CYCLES = 0x3e,
	AUDIO_RAM_DUTY_PATTERNS = 0x46,
	AUDIO_RAM_VIBRATO_DELAYS = 0x4e,
	AUDIO_RAM_VIBRATO_EXTENTS = 0x56,
	AUDIO_RAM_VIBRATO_RATES = 0x5e,
	AUDIO_RAM_FREQUENCY_LOW = 0x66,
	AUDIO_RAM_VIBRATO_RELOADS = 0x6e,
	AUDIO_RAM_SLIDE_LENGTHS = 0x76,
	AUDIO_RAM_SLIDE_STEPS = 0x7e,
	AUDIO_RAM_SLIDE_FRACTIONS = 0x86,
	AUDIO_RAM_CURRENT_FRACTIONS = 0x8e,
	AUDIO_RAM_CURRENT_HIGH = 0x96,
	AUDIO_RAM_CURRENT_LOW = 0x9e,
	AUDIO_RAM_TARGET_HIGH = 0xa6,
	AUDIO_RAM_TARGET_LOW = 0xae,
	AUDIO_RAM_NOTE_DELAYS = 0xb6,
	AUDIO_RAM_LOOP_COUNTERS = 0xbe,
	AUDIO_RAM_NOTE_SPEEDS = 0xc6,
	AUDIO_RAM_FRACTIONAL_DELAYS = 0xce,
	AUDIO_RAM_MUSIC_INSTRUMENT = 0xe6,
	AUDIO_RAM_SFX_INSTRUMENT = 0xe7,
	AUDIO_RAM_MUSIC_TEMPO = 0xe8,
	AUDIO_RAM_SFX_TEMPO = 0xea,
	AUDIO_RAM_SFX_HEADER = 0xec,
};

static port_u16
audio_register_hl(const struct cpu_register_state *registers)
{
	return ((port_u16)registers->h << 8) | registers->l;
}

static void
audio_set_register_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

static void
audio_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = audio_register_hl(registers);
	port_u16 result = left + right;
	port_u8 flags = registers->f & PORT_FLAG_Z;

	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		flags |= PORT_FLAG_H;
	if (result < left)
		flags |= PORT_FLAG_C;
	registers->f = flags;
	audio_set_register_hl(registers, result);
}

static port_u8
audio_rotate_left_circular(struct cpu_register_state *registers, port_u8 value)
{
	registers->f = value & 0x80 ? PORT_FLAG_C : 0;
	return (port_u8)((value << 1) | (value >> 7));
}

static void
audio_play_sound_fill(
	struct audio_play_sound_state *state,
	port_u8 offset,
	port_u8 count,
	port_u8 value)
{
	port_u8 old_flags = state->registers.f;
	port_u8 remaining = count;

	state->registers.d = count;
	state->registers.b = count;
	audio_set_register_hl(&state->registers, 0xc000 + offset);
	do {
		state->audio_ram[offset++] = value;
		remaining--;
		state->registers.f = audio_dec_flags(old_flags, remaining + 1);
		old_flags = state->registers.f;
	} while (remaining != 0);
	state->registers.b = 0;
	audio_set_register_hl(&state->registers, 0xc000 + offset);
}

static port_u8
audio_play_sound_header(
	const struct audio_play_sound_state *state, port_u16 address)
{
	return state->header_rom[address - 0x4000];
}

static void
audio_play_sound_common(
	struct audio_play_sound_state *state, port_u16 cry_ret_address)
{
	port_u8 sound_id = state->audio_ram[AUDIO_RAM_SOUND_ID];
	port_u8 header;
	port_u8 channels;
	port_u8 channel;
	port_u16 pointer;
	port_u16 command_pointer;

	state->registers.a = sound_id;
	state->registers.l = state->registers.a;
	state->registers.e = state->registers.a;
	state->registers.h = 0;
	state->registers.d = state->registers.h;
	audio_add_hl(&state->registers, audio_register_hl(&state->registers));
	audio_add_hl(&state->registers, state->registers.e);
	audio_add_hl(&state->registers, 0x4000);
	pointer = audio_register_hl(&state->registers);
	state->registers.e = state->registers.l;
	state->registers.d = state->registers.h;
	audio_set_register_hl(&state->registers, 0xc006);
	header = audio_play_sound_header(state, pointer++);
	state->registers.a = header;
	state->registers.b = state->registers.a;
	state->registers.a = audio_rotate_left_circular(
		&state->registers, state->registers.a);
	state->registers.a = audio_rotate_left_circular(
		&state->registers, state->registers.a);
	state->registers.a &= 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.c = state->registers.a;
	state->registers.a = state->registers.b & 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.b = state->registers.c + 1;
	state->registers.f = audio_inc_flags(
		state->registers.f, state->registers.c);
	state->registers.c = 0;
	channels = state->registers.b;
	command_pointer = 0xc006;

	for (;;) {
		channel = state->registers.a;
		state->registers.f = audio_cp_flags(channel, state->registers.c);
		while (channel != state->registers.c) {
			port_u8 value = state->registers.c;
			state->registers.c = value + 1;
			state->registers.f = audio_inc_flags(
				state->registers.f, value);
			command_pointer += 2;
			audio_set_register_hl(&state->registers, command_pointer);
			state->registers.f = audio_cp_flags(
				channel, state->registers.c);
		}
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, channel);

		state->registers.b = 0;
		state->registers.c = channel;
		audio_set_register_hl(&state->registers, 0xc026);
		audio_add_hl(&state->registers, state->registers.c);
		state->registers.a = sound_id;
		state->audio_ram[AUDIO_RAM_SOUND_IDS + channel] = sound_id;
		state->registers.a = channel;
		state->registers.f = audio_cp_flags(channel, 3);
		if (channel >= 3) {
			audio_set_register_hl(&state->registers, 0xc02e);
			audio_add_hl(&state->registers, state->registers.c);
			state->audio_ram[AUDIO_RAM_FLAGS1 + channel] |= 4;
		}

		/* POP BC restores the header's remaining channel count. */
		state->registers.b = channels;
		state->registers.c = channel;
		audio_set_register_hl(&state->registers, command_pointer);
		state->registers.a = audio_play_sound_header(state, pointer++);
		state->audio_ram[command_pointer - 0xc000] = state->registers.a;
		command_pointer++;
		audio_set_register_hl(&state->registers, command_pointer);
		state->registers.a = audio_play_sound_header(state, pointer++);
		state->audio_ram[command_pointer - 0xc000] = state->registers.a;
		command_pointer++;
		audio_set_register_hl(&state->registers, command_pointer);
		state->registers.c++;
		state->registers.b--;
		channels = state->registers.b;
		state->registers.f = audio_dec_flags(
			state->registers.f, state->registers.b + 1);
		state->registers.a = state->registers.b;
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
		state->registers.a = audio_play_sound_header(state, pointer++);
		state->registers.d = (port_u8)(pointer >> 8);
		state->registers.e = (port_u8)pointer;
		if (state->registers.b == 0)
			break;
		header = state->registers.a;
		channel = header;
	}

	state->registers.a = sound_id;
	state->registers.f = audio_cp_flags(sound_id, 0x14);
	if (sound_id >= 0x14) {
		state->registers.a = sound_id;
		state->registers.f = audio_cp_flags(sound_id, 0x86);
		if (sound_id < 0x86) {
			port_u8 i;

			audio_set_register_hl(&state->registers, 0xc02a);
			for (i = 4; i != 8; i++) {
				state->audio_ram[AUDIO_RAM_SOUND_IDS + i] = sound_id;
				state->registers.l++;
			}
			audio_set_register_hl(&state->registers, 0xc012);
			state->registers.e = (port_u8)cry_ret_address;
			state->registers.d = (port_u8)(cry_ret_address >> 8);
			state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + 12] =
				state->registers.e;
			state->registers.l++;
			state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + 13] =
				state->registers.d;
			state->registers.a =
				state->audio_ram[AUDIO_RAM_SAVED_VOLUME];
			state->registers.f = PORT_FLAG_H;
			if (state->registers.a == 0) {
				state->registers.f |= PORT_FLAG_Z;
				state->registers.a = state->hardware_audio[0x14];
				state->audio_ram[AUDIO_RAM_SAVED_VOLUME] =
					state->registers.a;
				state->registers.a = 0x77;
				state->hardware_audio[0x14] = 0x77;
			}
		}
	}
}

static void
audio_play_sound_stop(struct audio_play_sound_state *state)
{
	state->registers.a = 0x80;
	state->hardware_audio[0x16] = state->registers.a;
	state->hardware_audio[0x0a] = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->hardware_audio[0x15] = 0;
	state->hardware_audio[0x0c] = 0;
	state->registers.a = 0x08;
	state->hardware_audio[0x00] = state->registers.a;
	state->hardware_audio[0x02] = state->registers.a;
	state->hardware_audio[0x07] = state->registers.a;
	state->hardware_audio[0x11] = state->registers.a;
	state->registers.a = 0x40;
	state->hardware_audio[0x04] = state->registers.a;
	state->hardware_audio[0x09] = state->registers.a;
	state->hardware_audio[0x13] = state->registers.a;
	state->registers.a = 0x77;
	state->hardware_audio[0x14] = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->audio_ram[AUDIO_RAM_UNUSED] = 0;
	state->audio_ram[AUDIO_RAM_DISABLE_OUTPUT] = 0;
	state->audio_ram[AUDIO_RAM_MUTE] = 0;
	state->audio_ram[AUDIO_RAM_MUSIC_TEMPO + 1] = 0;
	state->audio_ram[AUDIO_RAM_SFX_TEMPO + 1] = 0;
	state->audio_ram[AUDIO_RAM_MUSIC_INSTRUMENT] = 0;
	state->audio_ram[AUDIO_RAM_SFX_INSTRUMENT] = 0;
	audio_play_sound_fill(
		state, AUDIO_RAM_COMMAND_POINTERS, 0xa0, 0);
	state->registers.a = 1;
	audio_play_sound_fill(state, AUDIO_RAM_NOTE_DELAYS, 0x18, 1);
	state->audio_ram[AUDIO_RAM_MUSIC_TEMPO] = 1;
	state->audio_ram[AUDIO_RAM_SFX_TEMPO] = 1;
	state->registers.a = 0xff;
	state->audio_ram[AUDIO_RAM_STEREO] = 0xff;
}

static void
audio_play_sound_music(
	struct audio_play_sound_state *state, port_u16 cry_ret_address)
{
	static const port_u8 music_clear_offsets[] = {
		AUDIO_RAM_SOUND_IDS, AUDIO_RAM_FLAGS1, AUDIO_RAM_DUTY_CYCLES,
		AUDIO_RAM_DUTY_PATTERNS, AUDIO_RAM_VIBRATO_DELAYS,
		AUDIO_RAM_VIBRATO_EXTENTS, AUDIO_RAM_VIBRATO_RATES,
		AUDIO_RAM_FREQUENCY_LOW, AUDIO_RAM_VIBRATO_RELOADS,
		AUDIO_RAM_FLAGS2, AUDIO_RAM_SLIDE_LENGTHS,
		AUDIO_RAM_SLIDE_STEPS, AUDIO_RAM_SLIDE_FRACTIONS,
		AUDIO_RAM_CURRENT_FRACTIONS, AUDIO_RAM_CURRENT_HIGH,
		AUDIO_RAM_CURRENT_LOW, AUDIO_RAM_TARGET_HIGH,
		AUDIO_RAM_TARGET_LOW,
	};
	port_u8 i;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->audio_ram[AUDIO_RAM_UNUSED] = 0;
	state->audio_ram[AUDIO_RAM_DISABLE_OUTPUT] = 0;
	state->audio_ram[AUDIO_RAM_MUSIC_TEMPO + 1] = 0;
	state->audio_ram[AUDIO_RAM_MUSIC_INSTRUMENT] = 0;
	state->audio_ram[AUDIO_RAM_SFX_INSTRUMENT] = 0;
	audio_play_sound_fill(state, AUDIO_RAM_RETURN_ADDRESSES, 8, 0);
	audio_play_sound_fill(state, AUDIO_RAM_COMMAND_POINTERS, 8, 0);
	for (i = 0; i != sizeof(music_clear_offsets); i++)
		audio_play_sound_fill(state, music_clear_offsets[i], 4, 0);
	state->registers.a = 1;
	audio_play_sound_fill(state, AUDIO_RAM_LOOP_COUNTERS, 4, 1);
	audio_play_sound_fill(state, AUDIO_RAM_NOTE_DELAYS, 4, 1);
	audio_play_sound_fill(state, AUDIO_RAM_NOTE_SPEEDS, 4, 1);
	state->audio_ram[AUDIO_RAM_MUSIC_TEMPO] = 1;
	state->registers.a = 0xff;
	state->audio_ram[AUDIO_RAM_STEREO] = 0xff;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->hardware_audio[0x14] = 0;
	state->registers.a = 0x08;
	state->hardware_audio[0x00] = state->registers.a;
	state->registers.a = 0;
	state->hardware_audio[0x15] = 0;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->hardware_audio[0x0a] = 0;
	state->registers.a = 0x80;
	state->hardware_audio[0x0a] = state->registers.a;
	state->registers.a = 0x77;
	state->hardware_audio[0x14] = state->registers.a;
	audio_play_sound_common(state, cry_ret_address);
}

static void
audio_play_sound_clear_channel(
	struct audio_play_sound_state *state, port_u8 channel)
{
	static const port_u8 byte_offsets[] = {
		AUDIO_RAM_SOUND_IDS, AUDIO_RAM_FLAGS1, AUDIO_RAM_DUTY_CYCLES,
		AUDIO_RAM_DUTY_PATTERNS, AUDIO_RAM_VIBRATO_DELAYS,
		AUDIO_RAM_VIBRATO_EXTENTS, AUDIO_RAM_VIBRATO_RATES,
		AUDIO_RAM_FREQUENCY_LOW, AUDIO_RAM_VIBRATO_RELOADS,
		AUDIO_RAM_SLIDE_LENGTHS, AUDIO_RAM_SLIDE_STEPS,
		AUDIO_RAM_SLIDE_FRACTIONS, AUDIO_RAM_CURRENT_FRACTIONS,
		AUDIO_RAM_CURRENT_HIGH, AUDIO_RAM_CURRENT_LOW,
		AUDIO_RAM_TARGET_HIGH, AUDIO_RAM_TARGET_LOW, AUDIO_RAM_FLAGS2,
	};
	port_u8 i;
	port_u8 pair_offset = channel * 2;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.d = 0;
	state->registers.e = channel;
	audio_set_register_hl(&state->registers, pair_offset);
	audio_add_hl(&state->registers, audio_register_hl(&state->registers));
	state->registers.d = state->registers.h;
	state->registers.e = state->registers.l;
	state->audio_ram[AUDIO_RAM_RETURN_ADDRESSES + pair_offset] = 0;
	state->audio_ram[AUDIO_RAM_RETURN_ADDRESSES + pair_offset + 1] = 0;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + pair_offset] = 0;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + pair_offset + 1] = 0;
	for (i = 0; i != sizeof(byte_offsets); i++)
		state->audio_ram[byte_offsets[i] + channel] = 0;
	state->registers.a = 1;
	state->audio_ram[AUDIO_RAM_LOOP_COUNTERS + channel] = 1;
	state->audio_ram[AUDIO_RAM_NOTE_DELAYS + channel] = 1;
	state->audio_ram[AUDIO_RAM_NOTE_SPEEDS + channel] = 1;
	state->registers.a = channel;
	state->registers.f = audio_cp_flags(channel, 4);
	if (channel == 4) {
		state->registers.a = 0x08;
		state->hardware_audio[0x00] = state->registers.a;
	}
	/* The last store leaves HL at the selected note-speed byte. */
	audio_set_register_hl(
		&state->registers, 0xc000 + AUDIO_RAM_NOTE_SPEEDS + channel);
}

static void
audio_play_sound_sfx(
	struct audio_play_sound_state *state,
	port_u16 cry_ret_address)
{
	port_u8 sound_id = state->audio_ram[AUDIO_RAM_SOUND_ID];
	port_u16 header_pointer = 0x4000 + (port_u16)sound_id * 3;
	port_u8 header;
	port_u8 count_index;

	state->registers.a = sound_id;
	state->registers.l = state->registers.a;
	state->registers.e = state->registers.a;
	state->registers.h = 0;
	state->registers.d = state->registers.h;
	audio_add_hl(&state->registers, audio_register_hl(&state->registers));
	audio_add_hl(&state->registers, state->registers.e);
	audio_add_hl(&state->registers, 0x4000);
	state->audio_ram[AUDIO_RAM_SFX_HEADER] = state->registers.h;
	state->audio_ram[AUDIO_RAM_SFX_HEADER + 1] = state->registers.l;
	header = audio_play_sound_header(state, header_pointer);
	state->registers.a = header & 0xc0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = audio_rotate_left_circular(
		&state->registers, state->registers.a);
	state->registers.a = audio_rotate_left_circular(
		&state->registers, state->registers.a);
	count_index = state->registers.a;
	state->registers.c = count_index;

	for (;;) {
		port_u8 channel;
		port_u8 current_sound;
		port_u16 entry_pointer;
		port_u8 left;

		state->registers.d = state->registers.c;
		state->registers.a = state->registers.c;
		left = state->registers.a;
		state->registers.a += state->registers.a;
		state->registers.f = audio_add_flags(left, left);
		left = state->registers.a;
		state->registers.a += state->registers.c;
		state->registers.f = audio_add_flags(left, state->registers.c);
		state->registers.c = state->registers.a;
		state->registers.b = 0;
		state->registers.h = state->audio_ram[AUDIO_RAM_SFX_HEADER];
		state->registers.l = state->audio_ram[AUDIO_RAM_SFX_HEADER + 1];
		audio_add_hl(&state->registers, state->registers.c);
		entry_pointer = audio_register_hl(&state->registers);
		state->registers.c = state->registers.d;
		state->registers.a =
			audio_play_sound_header(state, entry_pointer) & 0x0f;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		channel = state->registers.a;
		state->registers.e = channel;
		state->registers.d = 0;
		audio_set_register_hl(&state->registers, 0xc026);
		audio_add_hl(&state->registers, channel);
		current_sound = state->audio_ram[AUDIO_RAM_SOUND_IDS + channel];
		state->registers.a = current_sound;
		state->registers.f = PORT_FLAG_H;
		if (current_sound == 0)
			state->registers.f |= PORT_FLAG_Z;
		if (current_sound != 0) {
			state->registers.a = channel;
			state->registers.f = audio_cp_flags(channel, 7);
			if (channel == 7) {
				state->registers.a = sound_id;
				state->registers.f = audio_cp_flags(sound_id, 0x14);
				if (sound_id < 0x14)
					return;
				state->registers.a = current_sound;
				state->registers.f = audio_cp_flags(current_sound, 0x14);
				if (current_sound <= 0x14)
					goto play_channel;
			}
			state->registers.a = sound_id;
			state->registers.f = audio_cp_flags(sound_id, current_sound);
			if (sound_id > current_sound)
				return;
		}
play_channel:
		audio_play_sound_clear_channel(state, channel);
		state->registers.a = state->registers.c;
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
		if (state->registers.c == 0) {
			audio_play_sound_common(state, cry_ret_address);
			return;
		}
		left = state->registers.c;
		state->registers.c--;
		state->registers.f = audio_dec_flags(state->registers.f, left);
	}
}

static void
audio_play_sound(
	struct audio_play_sound_state *state,
	port_u8 maximum_sfx,
	port_u16 cry_ret_address)
{
	port_u8 sound_id = state->registers.a;

	state->audio_ram[AUDIO_RAM_SOUND_ID] = sound_id;
	state->registers.f = audio_cp_flags(sound_id, 0xff);
	if (sound_id == 0xff) {
		audio_play_sound_stop(state);
		return;
	}
	state->registers.f = audio_cp_flags(sound_id, maximum_sfx);
	if (sound_id <= maximum_sfx) {
		audio_play_sound_sfx(state, cry_ret_address);
		return;
	}
	state->registers.f = audio_cp_flags(sound_id, 0xfe);
	if (sound_id == 0xfe || sound_id < 0xfe) {
		audio_play_sound_music(state, cry_ret_address);
		return;
	}
	audio_play_sound_sfx(state, cry_ret_address);
}

__attribute__((noinline, used)) void
port_audio1_play_sound(struct audio_play_sound_state *state)
{
	audio_play_sound(state, 0xb9, 0x5b16);
}

__attribute__((noinline, used)) void
port_audio2_play_sound(struct audio_play_sound_state *state)
{
	audio_play_sound(state, 0xe9, 0x62d5);
}

__attribute__((noinline, used)) void
port_audio3_play_sound(struct audio_play_sound_state *state)
{
	audio_play_sound(state, 0xc2, 0x5b8a);
}

static void
audio_unknown_ef_get_next(struct audio_unknown_ef_state *state)
{
	port_u8 channel = state->registers.c;
	port_u8 offset = channel * 2;
	port_u16 pointer =
		state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset] |
		((port_u16)state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset + 1]
		 << 8);

	state->registers.f = channel == 0 ? PORT_FLAG_Z : 0;
	state->registers.a = state->command_byte;
	pointer++;
	state->registers.d = (port_u8)(pointer >> 8);
	state->registers.e = (port_u8)pointer;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset] =
		state->registers.e;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset + 1] =
		state->registers.d;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
}

static void
audio_unknown_ef(struct audio_unknown_ef_state *state, port_u8 variant)
{
	port_u8 saved_b;
	port_u8 saved_c;
	port_u16 i;
	struct audio_play_sound_state play;

	state->registers.f = audio_cp_flags(state->registers.a, 0xef);
	if (state->registers.a != 0xef) {
		state->continuation = AUDIO_CONTINUE_DUTY_CYCLE_PATTERN;
		return;
	}
	audio_unknown_ef_get_next(state);
	saved_b = state->registers.b;
	saved_c = state->registers.c;
	play.registers = state->registers;
	for (i = 0; i != 243; i++)
		play.audio_ram[i] = state->audio_ram[i];
	for (i = 0; i != 23; i++)
		play.hardware_audio[i] = state->hardware_audio[i];
	for (i = 0; i != 784; i++)
		play.header_rom[i] = state->header_rom[i];
	if (variant == 1)
		port_audio1_play_sound(&play);
	else if (variant == 2)
		port_audio2_play_sound(&play);
	else
		port_audio3_play_sound(&play);
	state->registers = play.registers;
	for (i = 0; i != 243; i++)
		state->audio_ram[i] = play.audio_ram[i];
	for (i = 0; i != 23; i++)
		state->hardware_audio[i] = play.hardware_audio[i];
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.a = state->audio_ram[AUDIO_RAM_DISABLE_OUTPUT];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.a = state->audio_ram[AUDIO_RAM_SOUND_IDS + 7];
		state->audio_ram[AUDIO_RAM_DISABLE_OUTPUT] = state->registers.a;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		state->audio_ram[AUDIO_RAM_SOUND_IDS + 7] = 0;
	}
	state->continuation = AUDIO_CONTINUE_SOUND_RET;
}

__attribute__((noinline, used)) void
port_audio1_unknownmusic0xef(struct audio_unknown_ef_state *state)
{
	audio_unknown_ef(state, 1);
}

__attribute__((noinline, used)) void
port_audio2_unknownmusic0xef(struct audio_unknown_ef_state *state)
{
	audio_unknown_ef(state, 2);
}

__attribute__((noinline, used)) void
port_audio3_unknownmusic0xef(struct audio_unknown_ef_state *state)
{
	audio_unknown_ef(state, 3);
}

static void
audio_note_get_next(struct audio_note_state *state)
{
	port_u8 channel = state->registers.c;
	port_u8 offset = channel * 2;
	port_u16 pointer =
		state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset] |
		((port_u16)state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset + 1]
		 << 8);

	state->registers.f = channel == 0 ? PORT_FLAG_Z : 0;
	state->registers.a = state->command_byte;
	pointer++;
	state->registers.d = (port_u8)(pointer >> 8);
	state->registers.e = (port_u8)pointer;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset] =
		state->registers.e;
	state->audio_ram[AUDIO_RAM_COMMAND_POINTERS + offset + 1] =
		state->registers.d;
	state->registers.h = 0xc0;
	state->registers.l = 0x07 + offset;
}

__attribute__((noinline, used)) void
port_audio_note_play_sound(struct audio_note_state *state, port_u8 variant)
{
	port_u16 i;
	struct audio_play_sound_state play;

	play.registers = state->registers;
	for (i = 0; i != 243; i++)
		play.audio_ram[i] = state->audio_ram[i];
	for (i = 0; i != 23; i++)
		play.hardware_audio[i] = state->hardware_audio[i];
	for (i = 0; i != 784; i++)
		play.header_rom[i] = state->header_rom[i];
	if (variant == 1)
		port_audio1_play_sound(&play);
	else if (variant == 2)
		port_audio2_play_sound(&play);
	else
		port_audio3_play_sound(&play);
	state->registers = play.registers;
	for (i = 0; i != 243; i++)
		state->audio_ram[i] = play.audio_ram[i];
	for (i = 0; i != 23; i++)
		state->hardware_audio[i] = play.hardware_audio[i];
}

static void
audio_note(struct audio_note_state *state, port_u8 variant)
{
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;

	state->registers.a = state->registers.c;
	state->registers.f = audio_cp_flags(state->registers.a, 3);
	if (state->registers.c != 3) {
		state->continuation = AUDIO_CONTINUE_NOTE_LENGTH;
		return;
	}
	state->registers.a = state->registers.d & 0xf0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.f = audio_cp_flags(state->registers.a, 0xb0);
	if (state->registers.a > 0xb0) {
		state->continuation = AUDIO_CONTINUE_NOTE_LENGTH;
		return;
	}
	if (state->registers.a < 0xb0) {
		port_u8 value = state->registers.a;
		state->registers.a = (port_u8)((value << 4) | (value >> 4));
		state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
		state->registers.b = state->registers.a;
		state->registers.a = state->registers.d & 0x0f;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		state->registers.d = state->registers.a;
		state->registers.a = state->registers.b;
		saved_d = state->registers.d;
		saved_e = state->registers.e;
		saved_b = state->registers.b;
		saved_c = state->registers.c;
	} else {
		state->registers.a = state->registers.d & 0x0f;
		state->registers.f = PORT_FLAG_H;
		if (state->registers.a == 0)
			state->registers.f |= PORT_FLAG_Z;
		saved_d = state->registers.a;
		saved_e = state->registers.f;
		saved_b = state->registers.b;
		saved_c = state->registers.c;
		audio_note_get_next(state);
	}
	state->registers.d = state->registers.a;
	state->registers.a = state->audio_ram[AUDIO_RAM_DISABLE_OUTPUT];
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->registers.a = state->registers.d;
		port_audio_note_play_sound(state, variant);
	}
	state->registers.b = saved_b;
	state->registers.c = saved_c;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
	state->continuation = AUDIO_CONTINUE_NOTE_LENGTH;
}

__attribute__((noinline, used)) void
port_audio1_note(struct audio_note_state *state)
{
	audio_note(state, 1);
}

__attribute__((noinline, used)) void
port_audio2_note(struct audio_note_state *state)
{
	audio_note(state, 2);
}

__attribute__((noinline, used)) void
port_audio3_note(struct audio_note_state *state)
{
	audio_note(state, 3);
}
