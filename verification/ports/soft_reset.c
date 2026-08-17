#include "port_state.h"

/* Port of SoftReset in home/init.asm.
 *
 * SoftReset stops all sound, fades the palette out, waits a few frames, then
 * falls through directly into Init (no jp). Its deterministic observable
 * memory effect is StopAllSounds' audio-state writes; GBPalWhiteOut (palette
 * fade) and DelayFrames (timing) have no deterministic memory effect modeled
 * here. The fallthrough into Init is a separate port (port_init). The
 * equivalence proof for SoftReset is pending. */

#define W_AUDIO_ROM_BANK          0xc0efu
#define W_AUDIO_SAVED_ROM_BANK    0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL  0xcfc7u
#define W_NEW_SOUND_ID            0xc0eeu
#define W_LAST_MUSIC_SOUND_ID     0xcfcau

__attribute__((noinline, used)) void
port_soft_reset(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* call StopAllSounds */
	memory[W_AUDIO_ROM_BANK] = 2;          /* BANK("Audio Engine 1") */
	memory[W_AUDIO_SAVED_ROM_BANK] = 2;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_NEW_SOUND_ID] = 0;
	memory[W_LAST_MUSIC_SOUND_ID] = 0;
	/* dec a -> A = 0xFF; jp PlaySound (SFX_STOP_ALL_MUSIC) is not modeled. */

	/* call GBPalWhiteOut -- palette fade, not modeled. */
	/* ld c, 32; call DelayFrames -- timing, not modeled. */

	/* (falls through into Init, which is ported separately) */
}
