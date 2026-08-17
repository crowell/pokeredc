#include "port_state.h"

/*
 * Port of Music_RivalAlternateStartAndTempo in audio/alternate_tempo.asm.
 *
 * Runs the alternate "start" (Music_RivalAlternateStart), which sets the
 * channel 1/2/3 command pointers to the alternate-start measures, then resets
 * hl to wChannelCommandPointers and overwrites only channel 1 with the combined
 * "start and tempo" measure (so Ch1 uses the combined variant while Ch2/Ch3
 * keep their alternate-start values).
 *
 * The forwarded call reuses the Music_RivalAlternateStart port; this wrapper
 * then performs the final Ch1 overwrite. See music_rival_alternate_start.c for
 * the notes on the reproduced PlayMusic globals and overwrite convention.
 */

#define W_CHANNEL_COMMAND_POINTERS 0xc006u

#define RIVAL_CH1_ALTERNATE_START_AND_TEMPO 0x719bu

/* Forward declaration: the alternate-start routine is its own port. */
__attribute__((noinline, used)) void
port_music_rival_alternate_start(struct cpu_register_state *state,
	port_u8 *memory);

static port_u16
overwrite_channel(port_u8 *memory, port_u16 hl, port_u16 value)
{
	memory[hl] = (port_u8)value;
	memory[hl + 1] = (port_u8)(value >> 8);
	return (port_u16)(hl + 2);
}

__attribute__((noinline, used)) void
port_music_rival_alternate_start_and_tempo(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 hl;

	/* call Music_RivalAlternateStart (sets Ch1/Ch2/Ch3 to alternate start) */
	port_music_rival_alternate_start(state, memory);

	/* ld hl, wChannelCommandPointers (reset after the forwarded call) */
	hl = W_CHANNEL_COMMAND_POINTERS;

	/* jp Audio1_OverwriteChannelPointer (Ch1 only, combined variant) */
	hl = overwrite_channel(memory, hl, RIVAL_CH1_ALTERNATE_START_AND_TEMPO);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
