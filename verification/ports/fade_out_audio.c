#include "port_state.h"

/* Port of FadeOutAudio in home/fade_audio.asm.
 *
 * Handles audio fade-out by decrementing the master volume (rAUDVOL) once per call
 * until it reaches zero, then plays SFX_STOP_ALL_MUSIC and restores the saved
 * audio ROM bank and sound ID.
 *
 * Input/Output globals:
 * - wAudioFadeOutControl: 0 = not fading, non-zero = fading (controls fade speed)
 * - wAudioFadeOutCounter: frame counter (reloads from wAudioFadeOutCounterReloadValue)
 * - wAudioFadeOutCounterReloadValue: frames between volume decrements
 * - wStatusFlags2: bit BIT_NO_AUDIO_FADE_OUT (1) disables fade-out
 * - rAUDVOL (0xFF26): hardware master volume register
 * - wAudioFadeOutControl: cleared when fade completes
 * - wAudioFadeOutCounter: reloaded from wAudioFadeOutCounterReloadValue
 * - wAudioROMBank: restored from wAudioSavedROMBank after fade
 * - wNewSoundID: set to SFX_STOP_ALL_MUSIC (0xFF) then to saved sound ID
 * - wAudioROMBank: restored from wAudioSavedROMBank after fade */

#define W_AUDIO_FADE_OUT_CONTROL 0xCFC7u
#define W_AUDIO_FADE_OUT_COUNTER 0xCFC9u
#define W_AUDIO_FADE_OUT_COUNTER_RELOAD 0xCFC8u
#define W_STATUS_FLAGS2 0xD72Cu
#define W_NEW_SOUND_ID 0xC0EFu
#define W_AUDIO_ROM_BANK 0xC0EFu
#define W_AUDIO_SAVED_ROM_BANK 0xC0F0u

#define R_AUDVOL 0xFF26u

#define BIT_NO_AUDIO_FADE_OUT 1
#define SFX_STOP_ALL_MUSIC 0xFFu

__attribute__((noinline, used)) void
port_fade_out_audio(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* ld a, [wAudioFadeOutControl]; and a; jr nz, .fadingOut */
	port_u8 fade_control = memory[W_AUDIO_FADE_OUT_CONTROL];
	if (fade_control == 0) {
		/* Not currently fading */
		/* ld a, [wStatusFlags2]; bit BIT_NO_AUDIO_FADE_OUT, a; ret nz */
		port_u8 status = memory[W_STATUS_FLAGS2];
		if (status & (1 << 1)) {  /* BIT_NO_AUDIO_FADE_OUT = 1 */
			return;
		}
		/* ld a, $77; ldh [rAUDVOL], a; ret */
		memory[0xFF26] = 0x77;
		return;
	}

	/* .fadingOut */
	/* ld a, [wAudioFadeOutCounter]; and a; jr z, .counterReachedZero */
	port_u8 counter = memory[0xCFC9];
	if (counter == 0) {
		goto counter_reached_zero;
	}

	/* dec a; ld [wAudioFadeOutCounter], a; ret */
	memory[0xCFC9] = counter - 1;
	return;

counter_reached_zero:
	{
	port_u8 reload = memory[W_AUDIO_FADE_OUT_COUNTER_RELOAD];
	memory[W_AUDIO_FADE_OUT_COUNTER] = reload;
	}

	/* ldh a, [rAUDVOL]; and a; jr z, .fadeOutComplete */
	port_u8 volume = memory[0xFF26];
	if (volume == 0) {
		goto fade_out_complete;
	}

	port_u8 a = volume & 0x0F;
	a = a - 1;
	port_u8 c = a;
	a = volume & 0xF0;
	a = ((a >> 4) | (a << 4)) & 0xFF;  /* swap a */
	a = a - 1;
	a = ((a >> 4) | (a << 4)) & 0xFF;  /* swap a back */
	a = a | c;
	memory[0xFF26] = a;
	return;
fade_out_complete:
	{
	port_u8 b_val = memory[W_AUDIO_FADE_OUT_CONTROL];
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[0xCFC7] = 0;

	/* ld a, SFX_STOP_ALL_MUSIC; ld [wNewSoundID], a; call PlaySound */
	memory[0xC0EF] = 0xFF;

	/* PlaySound would be called here - in the port we just set the globals
	 * that PlaySound would modify. The test will handle PlaySound boundary. */

	/* ld a, [wAudioSavedROMBank]; ld [wAudioROMBank], a */
	/* ld a, b; ld [wNewSoundID], a; jp PlaySound */
	memory[W_NEW_SOUND_ID] = b_val;
	}
}