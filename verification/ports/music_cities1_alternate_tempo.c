#include "port_state.h"

/* Forward declaration of the ported DelayFrames leaf. */
__attribute__((noinline, used)) void
port_delay_frames(struct cpu_register_state *state, port_u8 *memory);

/*
 * Port of Music_Cities1AlternateTempo in audio/alternate_tempo.asm.
 *
 * Used for the Hall of Fame room: it arms an audio fade-out (reload value and
 * counter = 10, the fade-out control = $ff so music stops after the fade),
 * waits for the fade to finish, plays Cities1, and then overwrites the channel
 * 1 command pointer with the alternate "tempo" measure.
 *
 * The DelayFrames wait and the top-level PlayMusic globals are reproduced; the
 * deeper channel-initialization inside PlayMusic/PlaySound is owned by the
 * dedicated PlayMusic port. See music_rival_alternate_start.c for the
 * overwrite convention.
 */

#define W_CHANNEL_COMMAND_POINTERS        0xc006u
#define W_NEW_SOUND_ID                   0xc0eeu
#define W_AUDIO_ROM_BANK                 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK           0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL         0xcfc7u
#define W_AUDIO_FADE_OUT_COUNTER         0xcfc9u
#define W_AUDIO_FADE_OUT_COUNTER_RELOAD  0xcfc8u

#define BANK_MUSIC_CITIES1               0x02u
#define MUSIC_CITIES1                    0xc3u

#define CITIES1_CH1_ALTERNATE_TEMPO      0x6a6fu

static port_u16
overwrite_channel(port_u8 *memory, port_u16 hl, port_u16 value)
{
	memory[hl] = (port_u8)value;
	memory[hl + 1] = (port_u8)(value >> 8);
	return (port_u16)(hl + 2);
}

__attribute__((noinline, used)) void
port_music_cities1_alternate_tempo(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 hl;

	/* ld a, 10; ld [wAudioFadeOutCounterReloadValue], a; ld [wAudioFadeOutCounter], a */
	state->a = 10;
	memory[W_AUDIO_FADE_OUT_COUNTER_RELOAD] = state->a;
	memory[W_AUDIO_FADE_OUT_COUNTER] = state->a;

	/* ld a, $ff; ld [wAudioFadeOutControl], a */
	state->a = 0xff;
	memory[W_AUDIO_FADE_OUT_CONTROL] = state->a;

	/* ld c, 100; call DelayFrames */
	state->c = 100;
	port_delay_frames(state, memory);

	/* ld c, BANK(Music_Cities1); ld a, MUSIC_CITIES1; call PlayMusic */
	state->c = BANK_MUSIC_CITIES1;
	state->a = MUSIC_CITIES1;
	memory[W_NEW_SOUND_ID] = state->a;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_AUDIO_ROM_BANK] = state->c;
	memory[W_AUDIO_SAVED_ROM_BANK] = state->c;

	/* ld hl, wChannelCommandPointers */
	hl = W_CHANNEL_COMMAND_POINTERS;

	/* jp Audio1_OverwriteChannelPointer (Ch1 only) */
	hl = overwrite_channel(memory, hl, CITIES1_CH1_ALTERNATE_TEMPO);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
