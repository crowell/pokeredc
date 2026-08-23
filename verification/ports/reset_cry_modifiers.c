#include "port_state.h"

/* Port of ResetCryModifiers in engine/battle/core.asm:
 *
 *   xor a
 *   ld [wFrequencyModifier], a   ; $c0f1
 *   ld [wTempoModifier], a       ; $c0f2
 *   jp PlaySound                 ; proven tail composition
 */

void port_play_sound(struct play_sound_state *);

#define W_FREQUENCY_MODIFIER 0xc0f1u
#define W_TEMPO_MODIFIER     0xc0f2u

__attribute__((noinline, used)) void
port_reset_cry_modifiers(struct cpu_register_state *state, port_u8 *memory)
{
	state->a = 0;
	memory[W_FREQUENCY_MODIFIER] = 0;
	memory[W_TEMPO_MODIFIER] = 0;

	/* jp PlaySound (tail call into the proven port) */
	{
		struct play_sound_state ps;
		ps.registers = *state;
		ps.new_sound_id = memory[0xc0eeu];
		ps.audio_rom_bank = memory[0xc0efu];
		ps.fade_control = memory[0xcfc7u];
		ps.fade_reload = 0;
		ps.fade_counter = 0;
		ps.last_music_sound_id = 0;
		ps.channel_sound_ids[0] = 0;
		ps.channel_sound_ids[1] = 0;
		ps.channel_sound_ids[2] = 0;
		ps.channel_sound_ids[3] = 0;
		ps.saved_rom_bank = 0;
		ps.loaded_rom_bank = 0;
		ps.rom_bank = 0;
		ps.dispatch_called = 0;
		ps.low_health_alarm = 0;
		ps.audio_saved_rom_bank = 0;
		port_play_sound(&ps);
		*state = ps.registers;
	}
}
