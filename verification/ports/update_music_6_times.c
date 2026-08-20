#include "port_state.h"

/* Port of UpdateMusic6Times in home/audio.asm.
 *
 * Calls the appropriate audio engine update function (Audio1/2/3_UpdateMusic)
 * 6 times via Bankswitch. The audio ROM bank determines which engine is active.
 *
 * Modifies: A, B, C, H, L, F. Preserves other registers. */

#define W_AUDIO_ROM_BANK 0xC0EFu
#define BANK_AUDIO1_UPDATE 0x02u  /* BANK(Audio1_UpdateMusic) */
#define BANK_AUDIO2_UPDATE 0x08u  /* BANK(Audio2_UpdateMusic) */
#define BANK_AUDIO3_UPDATE 0x1Fu  /* BANK(Audio3_UpdateMusic) */

#define AUDIO1_UPDATE_MUSIC 0x4003u
#define AUDIO2_UPDATE_MUSIC 0x5879u
#define AUDIO3_UPDATE_MUSIC 0x7751u

#define BANKSWITCH 0x35D6u


__attribute__((noinline, used)) void
port_update_music_6_times(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;

	/* ld a, [wAudioROMBank]; ld b, a */
	port_u8 audio_bank = memory[0xC0EFu];
	state->a = audio_bank;
	state->b = audio_bank;

	/* Determine which audio engine is active */
	if (audio_bank == 0x02) {  /* BANK(Audio1_UpdateMusic) */
		state->h = (port_u8)(0x4003 >> 8);
		state->l = (port_u8)0x4003;
	} else if (audio_bank == 0x08) {  /* BANK(Audio2_UpdateMusic) */
		state->h = (port_u8)(0x5879 >> 8);
		state->l = (port_u8)0x5879;
	} else {  /* Audio3 */
		state->h = (port_u8)(0x7751 >> 8);
		state->l = (port_u8)0x7751;
	}

	/* Bankswitch is the explicit no-op callback boundary. */
	state->c = 0;
}