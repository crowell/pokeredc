#include "port_state.h"

/*
 * Port of Music_RivalAlternateTempo in audio/alternate_tempo.asm.
 *
 * Plays MeetRival then overwrites only the channel 1 command pointer with the
 * alternate "tempo" measure (a slightly slower first measure). See
 * music_rival_alternate_start.c for the notes on the reproduced PlayMusic
 * globals and the channel-pointer overwrite convention.
 */

#define W_CHANNEL_COMMAND_POINTERS 0xc006u
#define W_NEW_SOUND_ID             0xc0eeu
#define W_AUDIO_ROM_BANK           0xc0efu
#define W_AUDIO_SAVED_ROM_BANK     0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL   0xcfc7u

#define BANK_MUSIC_MEET_RIVAL      0x02u
#define MUSIC_MEET_RIVAL           0xdeu

#define RIVAL_CH1_ALTERNATE_TEMPO  0x7119u

static port_u16
overwrite_channel(port_u8 *memory, port_u16 hl, port_u16 value)
{
	memory[hl] = (port_u8)value;
	memory[hl + 1] = (port_u8)(value >> 8);
	return (port_u16)(hl + 2);
}

__attribute__((noinline, used)) void
port_music_rival_alternate_tempo(struct cpu_register_state *state,
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

	/* jp Audio1_OverwriteChannelPointer (Ch1 only) */
	hl = overwrite_channel(memory, hl, RIVAL_CH1_ALTERNATE_TEMPO);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
