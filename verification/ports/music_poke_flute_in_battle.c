#include "port_state.h"

/* Forward declaration of the ported PlaySoundWaitForCurrent leaf. */
__attribute__((noinline, used)) void
port_play_sound_wait_for_current(struct cpu_register_state *state,
	port_u8 *memory);

/*
 * Port of Music_PokeFluteInBattle in audio/poke_flute.asm.
 *
 * Begins playing the "caught mon" sound effect (PlaySoundWaitForCurrent), then
 * immediately overwrites the channel 5, 6 and 7 command pointers with the
 * pokeflute SFX data. The channel pointers are stored little-endian into
 * wChannelCommandPointers + CHAN5*2 (the value at [hl] is the low byte,
 * [hl+1] the high byte, and hl is advanced by 2 per channel).
 *
 * The forwarded PlaySoundWaitForCurrent call reuses its own port.
 */

#define W_CHANNEL_COMMAND_POINTERS 0xc006u
#define CHAN5                    4

#define POKE_FLUTE_CH5           0x6322u
#define POKE_FLUTE_CH6           0x6325u
#define POKE_FLUTE_CH7           0x449bu

static port_u16
overwrite_channel(port_u8 *memory, port_u16 hl, port_u16 value)
{
	memory[hl] = (port_u8)value;
	memory[hl + 1] = (port_u8)(value >> 8);
	return (port_u16)(hl + 2);
}

__attribute__((noinline, used)) void
port_music_poke_flute_in_battle(struct cpu_register_state *state,
	port_u8 *memory)
{
	port_u16 hl;

	/* ld a, SFX_CAUGHT_MON; call PlaySoundWaitForCurrent */
	state->a = 0x9au; /* SFX_CAUGHT_MON */
	port_play_sound_wait_for_current(state, memory);

	/* ld hl, wChannelCommandPointers + CHAN5 * 2 */
	hl = (port_u16)(W_CHANNEL_COMMAND_POINTERS + CHAN5 * 2);

	/* Audio2_OverwriteChannelPointer x3 (Ch5, Ch6, Ch7) */
	hl = overwrite_channel(memory, hl, POKE_FLUTE_CH5);
	hl = overwrite_channel(memory, hl, POKE_FLUTE_CH6);
	hl = overwrite_channel(memory, hl, POKE_FLUTE_CH7);

	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}
