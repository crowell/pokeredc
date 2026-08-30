#include "platform.h"

#include <string.h>

/*
 * Host implementation of the monochrome Game Boy APU.  It deliberately
 * consumes the same NR10..NR52 and wave-RAM bytes as the C ports, so the
 * ROM audio driver does not need a second, platform-specific sound API.
 *
 * Implemented hardware units:
 *   channel 1 pulse + frequency sweep
 *   channel 2 pulse
 *   channel 3 programmable 32-sample wave
 *   channel 4 15/7-bit LFSR noise
 *   length counters, volume envelopes, NR50 gain, and NR51 routing
 *
 * FIDELITY_BOUNDARY(audio-sequencer): Audio1_UpdateMusic and its command
 * readers are not C-ported yet.  Until they are, this file faithfully plays
 * register writes but cannot turn the ROM's music bytecode into those writes.
 * See verification/INTRO_MAIN_LOOP_PORTING.md.
 */

#define APU_SAMPLE_RATE 44100.0
#define SEQ_STEP_SECONDS (1.0 / 512.0)

#define R_NR10 0xFF10u
#define R_NR11 0xFF11u
#define R_NR12 0xFF12u
#define R_NR13 0xFF13u
#define R_NR14 0xFF14u
#define R_NR21 0xFF16u
#define R_NR22 0xFF17u
#define R_NR23 0xFF18u
#define R_NR24 0xFF19u
#define R_NR30 0xFF1Au
#define R_NR31 0xFF1Bu
#define R_NR32 0xFF1Cu
#define R_NR33 0xFF1Du
#define R_NR34 0xFF1Eu
#define R_NR41 0xFF20u
#define R_NR42 0xFF21u
#define R_NR43 0xFF22u
#define R_NR44 0xFF23u
#define R_NR50 0xFF24u
#define R_NR51 0xFF25u
#define R_NR52 0xFF26u
#define R_WAVE_RAM 0xFF30u

static const uint8_t duty_patterns[4] = {
	0x01u, /* 00000001: 12.5% */
	0x81u, /* 10000001: 25% */
	0x87u, /* 10000111: 50% */
	0x7Eu, /* 01111110: 75% */
};

static int16_t
clamp_s16(int value)
{
	if (value > 32767)
		return 32767;
	if (value < -32768)
		return -32768;
	return (int16_t)value;
}

static unsigned
pulse_frequency(const uint8_t *memory, unsigned channel)
{
	unsigned low = memory[channel == 0 ? R_NR13 : R_NR23];
	unsigned high = memory[channel == 0 ? R_NR14 : R_NR24] & 7u;

	return low | (high << 8);
}

static void
write_pulse_frequency(uint8_t *memory, unsigned channel, unsigned frequency)
{
	unsigned lo = channel == 0 ? R_NR13 : R_NR23;
	unsigned hi = channel == 0 ? R_NR14 : R_NR24;

	memory[lo] = (uint8_t)frequency;
	memory[hi] = (uint8_t)((memory[hi] & 0xF8u) | (frequency >> 8));
}

static unsigned
sweep_calculate(struct mac_apu *apu, const uint8_t *memory, int *overflow)
{
	unsigned shift = memory[R_NR10] & 7u;
	unsigned delta = apu->sweep_shadow >> shift;
	unsigned result;

	*overflow = 0;
	if ((memory[R_NR10] & 0x08u) != 0) {
		apu->sweep_negate_used = 1;
		result = apu->sweep_shadow - delta;
	} else {
		result = apu->sweep_shadow + delta;
	}
	if (result > 2047u)
		*overflow = 1;
	return result;
}

static void
trigger_pulse(struct mac_apu *apu, const uint8_t *memory, unsigned channel)
{
	unsigned nrx1 = channel == 0 ? R_NR11 : R_NR21;
	unsigned nrx2 = channel == 0 ? R_NR12 : R_NR22;
	unsigned length = 64u - (memory[nrx1] & 0x3Fu);

	apu->enabled[channel] = (memory[nrx2] & 0xF8u) != 0;
	apu->length_counter[channel] = length == 0 ? 64 : (int)length;
	apu->volume[channel] = (memory[nrx2] >> 4) & 15u;
	apu->env_timer[channel] = memory[nrx2] & 7u;
	if (apu->env_timer[channel] == 0)
		apu->env_timer[channel] = 8;
	apu->pulse_phase[channel] = 0.0;

	if (channel == 0) {
		int overflow = 0;
		unsigned period = (memory[R_NR10] >> 4) & 7u;

		apu->sweep_shadow = (uint16_t)pulse_frequency(memory, 0);
		apu->sweep_timer = period == 0 ? 8 : (int)period;
		apu->sweep_enabled = period != 0 || (memory[R_NR10] & 7u) != 0;
		apu->sweep_negate_used = 0;
		if ((memory[R_NR10] & 7u) != 0)
			(void)sweep_calculate(apu, memory, &overflow);
		if (overflow)
			apu->enabled[0] = 0;
	}
}

static void
trigger_wave(struct mac_apu *apu, const uint8_t *memory)
{
	unsigned length = 256u - memory[R_NR31];

	apu->enabled[2] = (memory[R_NR30] & 0x80u) != 0;
	apu->length_counter[2] = length == 0 ? 256 : (int)length;
	apu->wave_phase = 0.0;
}

static void
trigger_noise(struct mac_apu *apu, const uint8_t *memory)
{
	unsigned length = 64u - (memory[R_NR41] & 0x3Fu);

	apu->enabled[3] = (memory[R_NR42] & 0xF8u) != 0;
	apu->length_counter[3] = length == 0 ? 64 : (int)length;
	apu->volume[3] = (memory[R_NR42] >> 4) & 15u;
	apu->env_timer[3] = memory[R_NR42] & 7u;
	if (apu->env_timer[3] == 0)
		apu->env_timer[3] = 8;
	apu->noise_lfsr = 0x7FFFu;
	apu->noise_phase = 0.0;
}

/* Trigger bits behave like write strobes on the real hardware.  Clearing
 * them after observing the write prevents a flat memory register file from
 * retriggering a channel on every host audio callback. */
static void
consume_triggers(struct mac_apu *apu, uint8_t *memory)
{
	static const unsigned trigger_reg[4] = {
		R_NR14, R_NR24, R_NR34, R_NR44
	};

	for (unsigned channel = 0; channel < 4; channel++) {
		unsigned reg = trigger_reg[channel];
		uint8_t trigger = memory[reg] & 0x80u;

		if (trigger != 0) {
			if (channel < 2)
				trigger_pulse(apu, memory, channel);
			else if (channel == 2)
				trigger_wave(apu, memory);
			else
				trigger_noise(apu, memory);
			memory[reg] &= 0x7Fu;
		}
		apu->last_trigger[channel] = trigger;
	}
}

static void
clock_lengths(struct mac_apu *apu, const uint8_t *memory)
{
	static const unsigned control_reg[4] = {
		R_NR14, R_NR24, R_NR34, R_NR44
	};

	for (unsigned channel = 0; channel < 4; channel++) {
		if ((memory[control_reg[channel]] & 0x40u) != 0 &&
		    apu->length_counter[channel] > 0) {
			apu->length_counter[channel]--;
			if (apu->length_counter[channel] == 0)
				apu->enabled[channel] = 0;
		}
	}
}

static void
clock_envelope(struct mac_apu *apu, const uint8_t *memory, unsigned channel)
{
	unsigned reg = channel == 0 ? R_NR12 :
	    channel == 1 ? R_NR22 : R_NR42;
	unsigned period = memory[reg] & 7u;

	if (period == 0 || !apu->enabled[channel])
		return;
	if (--apu->env_timer[channel] > 0)
		return;
	apu->env_timer[channel] = (int)period;
	if ((memory[reg] & 0x08u) != 0) {
		if (apu->volume[channel] < 15)
			apu->volume[channel]++;
	} else if (apu->volume[channel] > 0) {
		apu->volume[channel]--;
	}
}

static void
clock_sweep(struct mac_apu *apu, uint8_t *memory)
{
	unsigned period = (memory[R_NR10] >> 4) & 7u;
	unsigned shift = memory[R_NR10] & 7u;
	unsigned frequency;
	int overflow;

	if (--apu->sweep_timer > 0)
		return;
	apu->sweep_timer = period == 0 ? 8 : (int)period;
	if (!apu->sweep_enabled || period == 0)
		return;

	frequency = sweep_calculate(apu, memory, &overflow);
	if (overflow) {
		apu->enabled[0] = 0;
		return;
	}
	if (shift != 0) {
		apu->sweep_shadow = (uint16_t)frequency;
		write_pulse_frequency(memory, 0, frequency);
		(void)sweep_calculate(apu, memory, &overflow);
		if (overflow)
			apu->enabled[0] = 0;
	}
}

static void
clock_frame_sequencer(struct mac_apu *apu, uint8_t *memory)
{
	if ((apu->seq_step & 1u) == 0)
		clock_lengths(apu, memory);
	if (apu->seq_step == 2u || apu->seq_step == 6u)
		clock_sweep(apu, memory);
	if (apu->seq_step == 7u) {
		clock_envelope(apu, memory, 0);
		clock_envelope(apu, memory, 1);
		clock_envelope(apu, memory, 3);
	}
	apu->seq_step = (apu->seq_step + 1u) & 7u;
}

static int
pulse_sample(struct mac_apu *apu, const uint8_t *memory, unsigned channel,
    double dt)
{
	unsigned nrx1 = channel == 0 ? R_NR11 : R_NR21;
	unsigned frequency = pulse_frequency(memory, channel);
	unsigned phase_index;
	double hz;
	int high;

	if (!apu->enabled[channel] || frequency >= 2048u)
		return 0;
	hz = 131072.0 / (2048.0 - (double)frequency);
	apu->pulse_phase[channel] += hz * dt;
	while (apu->pulse_phase[channel] >= 1.0)
		apu->pulse_phase[channel] -= 1.0;
	phase_index = (unsigned)(apu->pulse_phase[channel] * 8.0) & 7u;
	high = (duty_patterns[(memory[nrx1] >> 6) & 3u] >> phase_index) & 1u;
	return high ? apu->volume[channel] : -apu->volume[channel];
}

static int
wave_sample(struct mac_apu *apu, const uint8_t *memory, double dt)
{
	unsigned frequency = memory[R_NR33] | ((memory[R_NR34] & 7u) << 8);
	unsigned level = (memory[R_NR32] >> 5) & 3u;
	unsigned index;
	unsigned packed;
	unsigned sample;
	int centered;
	double hz;

	if (!apu->enabled[2] || (memory[R_NR30] & 0x80u) == 0 || level == 0 ||
	    frequency >= 2048u)
		return 0;
	hz = 65536.0 / (2048.0 - (double)frequency);
	apu->wave_phase += hz * dt;
	while (apu->wave_phase >= 1.0)
		apu->wave_phase -= 1.0;
	index = (unsigned)(apu->wave_phase * 32.0) & 31u;
	packed = memory[R_WAVE_RAM + index / 2u];
	sample = (index & 1u) != 0 ? packed & 15u : packed >> 4;
	centered = (int)sample - 8;
	return centered / (int)(1u << (level - 1u));
}

static int
noise_sample(struct mac_apu *apu, const uint8_t *memory, double dt)
{
	static const unsigned divisor[8] = { 8, 16, 32, 48, 64, 80, 96, 112 };
	unsigned nr43 = memory[R_NR43];
	unsigned shift = nr43 >> 4;
	double hz = 4194304.0 / (double)divisor[nr43 & 7u];

	if (!apu->enabled[3] || shift >= 14u)
		return 0;
	hz /= (double)(1u << (shift + 1u));
	apu->noise_phase += hz * dt;
	while (apu->noise_phase >= 1.0) {
		unsigned feedback = (apu->noise_lfsr ^ (apu->noise_lfsr >> 1)) & 1u;

		apu->noise_phase -= 1.0;
		apu->noise_lfsr = (uint16_t)((apu->noise_lfsr >> 1) |
		    (feedback << 14));
		if ((nr43 & 0x08u) != 0)
			apu->noise_lfsr = (uint16_t)((apu->noise_lfsr & ~(1u << 6)) |
			    (feedback << 6));
	}
	return (apu->noise_lfsr & 1u) == 0 ? apu->volume[3] : -apu->volume[3];
}

void
apu_init(struct mac_apu *apu)
{
	memset(apu, 0, sizeof(*apu));
	apu->noise_lfsr = 0x7FFFu;
}

void
apu_render(struct mac_apu *apu, uint8_t *memory, int16_t *out, size_t frames)
{
	const double dt = 1.0 / APU_SAMPLE_RATE;

	consume_triggers(apu, memory);
	for (size_t i = 0; i < frames; i++) {
		int channel[4];
		int left = 0;
		int right = 0;
		int mixed;

		if ((memory[R_NR52] & 0x80u) == 0) {
			memset(apu->enabled, 0, sizeof(apu->enabled));
			out[i] = 0;
			continue;
		}

		apu->seq_accum += dt;
		while (apu->seq_accum >= SEQ_STEP_SECONDS) {
			apu->seq_accum -= SEQ_STEP_SECONDS;
			clock_frame_sequencer(apu, memory);
		}

		channel[0] = pulse_sample(apu, memory, 0, dt);
		channel[1] = pulse_sample(apu, memory, 1, dt);
		channel[2] = wave_sample(apu, memory, dt);
		channel[3] = noise_sample(apu, memory, dt);
		for (unsigned ch = 0; ch < 4; ch++) {
			if ((memory[R_NR51] & (1u << (ch + 4u))) != 0)
				left += channel[ch];
			if ((memory[R_NR51] & (1u << ch)) != 0)
				right += channel[ch];
		}
		left *= (int)(((memory[R_NR50] >> 4) & 7u) + 1u);
		right *= (int)((memory[R_NR50] & 7u) + 1u);
		mixed = (left + right) * 96;
		out[i] = clamp_s16(mixed);
	}

	memory[R_NR52] = (uint8_t)((memory[R_NR52] & 0xF0u) |
	    (apu->enabled[0] ? 1u : 0u) |
	    (apu->enabled[1] ? 2u : 0u) |
	    (apu->enabled[2] ? 4u : 0u) |
	    (apu->enabled[3] ? 8u : 0u));
}

void
apu_test_tone(uint8_t *memory, unsigned tone_hz, unsigned ms)
{
	unsigned period;
	unsigned length_ticks = ms * 256u / 1000u;

	if (tone_hz < 65u)
		tone_hz = 65u;
	if (tone_hz > 131072u)
		tone_hz = 131072u;
	period = (unsigned)(2048.0 - 131072.0 / (double)tone_hz);
	if (period > 2047u)
		period = 2047u;

	memory[R_NR52] = 0x80u;
	memory[R_NR50] = 0x77u;
	memory[R_NR51] |= 0x11u;
	memory[R_NR11] = (uint8_t)(0x80u | ((64u - length_ticks) & 0x3Fu));
	memory[R_NR12] = 0xF3u;
	memory[R_NR13] = (uint8_t)period;
	memory[R_NR14] = (uint8_t)(0xC0u | (period >> 8));
}
