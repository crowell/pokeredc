#include "platform.h"

#include <string.h>

/*
 * Minimal APU synthesis: pulse channels 1 and 2 driven by the hardware
 * register file that lives in the flat memory at 0xFF10-0xFF3F. Wave (CH3)
 * and noise (CH4) are acknowledged but silent until the audio-engine ports
 * can drive them end-to-end; nothing reads those registers yet.
 *
 * Implemented register behavior:
 *   NRx1 duty + 6-bit sound length      NRx2 envelope + DAC enable
 *   NRx3 frequency low                  NRx4 trigger / length-enable / freq hi
 *   NR52 power switch.
 *
 * Timing follows the DMG frame sequencer: a 512 Hz clock of 8 steps; length
 * counts down on even steps, envelope updates on step 7.
 */

#define APU_SAMPLE_RATE 44100
#define SEQ_STEP_SEC (1.0 / 512.0)

static const uint8_t duty_table[4] = { 0x01, 0x03, 0x0F, 0x3F };

struct pulse_channel {
	uint8_t nr1, nr2, nr3, nr4;
};

/* NR registers for CH1 start at 0xFF11, CH2 at 0xFF16. */
static void
channel_regs(const uint8_t *memory, unsigned ch, struct pulse_channel *p)
{
	unsigned base = ch == 0 ? 0xFF11u : 0xFF16u;

	p->nr1 = memory[base];
	p->nr2 = memory[base + 1u];
	p->nr3 = memory[base + 2u];
	p->nr4 = memory[base + 3u];
}

void
apu_init(struct mac_apu *apu)
{
	memset(apu, 0, sizeof(*apu));
}

/* Trigger is edge-detected: NRx4 bit7 rising between sequencer steps
 * reloads length/volume/phase. The register file stays read-only here. */
static void
apu_trigger(struct mac_apu *st, unsigned ch, const struct pulse_channel *p)
{
	st->length_counter[ch] = (p->nr1 & 0x3Fu) != 0 ? p->nr1 & 0x3Fu : 64;
	st->volume[ch] = (int)((p->nr2 >> 4) & 15u);
	st->env_timer[ch] = p->nr2 & 7u;
	st->phase[ch] = 0.0;
}

static void
handle_trigger(struct mac_apu *st, unsigned ch,
	const struct pulse_channel *p)
{
	int was = st->last_nr14[ch] & 0x80;

	st->last_nr14[ch] = p->nr4;
	if (!was && (p->nr4 & 0x80u) != 0)
		apu_trigger(st, ch, p);
}

void
apu_render(struct mac_apu *apu, const uint8_t *memory, int16_t *out,
	size_t frames)
{
	const unsigned power = memory[0xFF26] & 0x80u;
	const double dt = 1.0 / (double)APU_SAMPLE_RATE;

	for (size_t i = 0; i < frames; i++) {
		int mixed = 0;

		apu->seq_accum += dt;
		while (apu->seq_accum >= SEQ_STEP_SEC) {
			apu->seq_accum -= SEQ_STEP_SEC;
			apu->seq_step = (apu->seq_step + 1u) & 7u;

			for (unsigned ch = 0; ch < 2; ch++) {
				struct pulse_channel p;

				channel_regs(memory, ch, &p);
				handle_trigger(apu, ch, &p);
				if ((apu->seq_step & 1u) == 0 &&
				    (p.nr4 & 0x40u) != 0 &&
				    apu->length_counter[ch] > 0)
					apu->length_counter[ch]--;
				if (apu->seq_step == 7u && (p.nr2 & 7u) != 0 &&
				    apu->env_timer[ch] > 0) {
					apu->env_timer[ch]--;
					if (apu->env_timer[ch] == 0) {
						apu->env_timer[ch] =
						    p.nr2 & 7u;
						if ((p.nr2 & 0x08u) != 0 &&
						    apu->volume[ch] < 15)
							apu->volume[ch]++;
						else if ((p.nr2 & 0x08u) ==
							0 &&
						    apu->volume[ch] > 0)
							apu->volume[ch]--;
					}
				}
			}
		}

		for (unsigned ch = 0; ch < 2; ch++) {
			struct pulse_channel p;
			unsigned period, hz;
			double wave;
			int audible;

			channel_regs(memory, ch, &p);
			if (!power || !(p.nr2 & 0xF8u))
				continue; /* power off or DAC disabled */
			if ((p.nr4 & 0x40u) != 0 &&
			    apu->length_counter[ch] == 0)
				continue; /* length expired */

			period = (((unsigned)p.nr4 & 7u) << 8) | p.nr3;
			hz = period >= 2048u ?
			    0 :
			    (unsigned)(131072.0 / (2048.0 - (double)period));
			if (hz == 0)
				continue;

			wave = (duty_table[(p.nr1 >> 6) & 3u] >>
				   (unsigned)(apu->phase[ch] * 8.0)) &
			    1u;
			audible = wave ? apu->volume[ch] : -apu->volume[ch];
			mixed += audible * (8000 / 15);

			apu->phase[ch] += (double)hz * dt;
			while (apu->phase[ch] >= 1.0)
				apu->phase[ch] -= 1.0;
		}
		out[i] = (int16_t)mixed;
	}
}

void
apu_test_tone(uint8_t *memory, unsigned tone_hz, unsigned ms)
{
	unsigned period;
	unsigned base = 0xFF11u; /* CH1 register block */
	unsigned length_ticks = ms * 256u / 1000u;

	if (tone_hz < 16u)
		tone_hz = 16u;
	if (tone_hz > 65535u)
		tone_hz = 65535u;
	period = (unsigned)(2048.0 - 131072.0 / (double)tone_hz);
	if (period > 2047u)
		period = 2047u;

	memory[base + 0u] = (port_u8)(0x80u | (length_ticks & 0x3F));
	memory[base + 1u] = 0xF3u; /* initial vol 15, decay, DAC on */
	memory[base + 2u] = (port_u8)(period & 0xFFu);
	memory[base + 3u] = (port_u8)(0xC0u | (period >> 8));
	memory[0xFF26u] |= 0x80u; /* APU power */
}
