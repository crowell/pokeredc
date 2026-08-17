#include "port_state.h"

/*
 * Port of Music_RivalAlternateStart in audio/alternate_tempo.asm.
 *
 * Plays MeetRival (music id MUSIC_MEET_RIVAL, in BANK(Music_MeetRival)) and
 * then overwrites the channel 1, 2 and 3 command pointers with the alternate
 * "start" measures. The alternate data pointers are the 16-bit addresses the
 * original stores little-endian into wChannelCommandPointers (the value at
 * [hl] is the low byte, [hl+1] the high byte, and hl is advanced by 2 per
 * channel).
 *
 * PlayMusic's unconditional top-level RAM writes (wNewSoundID, the audio ROM
 * bank globals and the fade-out control) are reproduced here; the deeper
 * channel-initialization performed inside PlayMusic/PlaySound is owned by the
 * dedicated PlayMusic port. The observable contract of this wrapper is the
 * wChannelCommandPointers overwrite plus those globals.
 */

#define W_CHANNEL_COMMAND_POINTERS 0xc006u
#define W_NEW_SOUND_ID             0xc0eeu
#define W_AUDIO_ROM_BANK           0xc0efu
#define W_AUDIO_SAVED_ROM_BANK     0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL   0xcfc7u

#define BANK_MUSIC_MEET_RIVAL      0x02u
#define MUSIC_MEET_RIVAL           0xdeu

#define RIVAL_CH1_ALTERNATE_START  0x71a2u
#define RIVAL_CH2_ALTERNATE_START  0x721du
#define RIVAL_CH3_ALTERNATE_START  0x72b5u

static port_u16
overwrite_channel(port_u8 *memory, port_u16 hl, port_u16 value)
{
	memory[hl] = (port_u8)value;
	memory[hl + 1] = (port_u8)(value >> 8);
	return (port_u16)(hl + 2);
}

__attribute__((noinline, used)) void
port_music_rival_alternate_start(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 hl;

	/* ld c, BANK(Music_MeetRival); ld a, MUSIC_MEET_RIVAL; call PlayMusic */
	state->c = BANK_MUSIC_MEET_RIVAL;
	state->a = MUSIC_MEET_RIVAL;
	memory[W_NEW_SOUND_ID] = state->a;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_AUDIO_ROM_BANK] = state->c;
	memory[W_AUDIO_SAVED_ROM_BANK] = state->c;

	/* ld hl, wChannelCommandPointers */
	hl = W_CHANNEL_COMMAND_POINTERS;

	/* Audio1_OverwriteChannelPointer x3 (Ch1, Ch2, Ch3) */
	hl = overwrite_channel(memory, hl, RIVAL_CH1_ALTERNATE_START);
	hl = overwrite_channel(memory, hl, RIVAL_CH2_ALTERNATE_START);
	hl = overwrite_channel(memory, hl, RIVAL_CH3_ALTERNATE_START);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
