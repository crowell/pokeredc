#include "port_state.h"

/* PlaySound dispatcher: implemented faithfully in play_sound.c. */
__attribute__((noinline, used)) void
port_play_sound(struct cpu_register_state *state, port_u8 *memory);

/*
 * Port of PlayBattleMusic in home/audio.asm.
 *
 * Stops the current music, then selects the battle theme from the active
 * opponent (gym leader, the rival's final battle, the champion Lance, a
 * normal trainer, or a wild Pokemon) and plays it. The sound is started
 * through PlayMusic -> PlaySound, which is modelled here by chaining
 * port_play_sound.
 */

#define W_AUDIO_FADE_OUT_CONTROL          0xcfc7u
#define W_LOW_HEALTH_ALARM               0xd083u
#define W_NEW_SOUND_ID                   0xc0eeu
#define W_AUDIO_ROM_BANK                 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK           0xc0f0u
#define W_CUR_OPPONENT                   0xd059u
#define W_GYM_LEADER_NO                  0xd05cu

#define MUSIC_GYM_LEADER_BATTLE       0xEAu
#define MUSIC_TRAINER_BATTLE          0xEDu
#define MUSIC_WILD_BATTLE             0xF0u
#define MUSIC_FINAL_BATTLE            0xF3u
#define SFX_STOP_ALL_MUSIC            0xFFu
#define BANK_MUSIC_GYM_LEADER_BATTLE  0x08u
#define OPP_ID_OFFSET 200u  /* 0xC8 */
#define OPP_RIVAL3    243u  /* 0xF3 = OPP_ID_OFFSET + RIVAL3 */
#define OPP_LANCE     247u  /* 0xF7 = OPP_ID_OFFSET + LANCE */

__attribute__((noinline, used)) void
port_play_battle_music(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 music_id;
	port_u8 bank = BANK_MUSIC_GYM_LEADER_BATTLE;

	/* xor a; ld [wAudioFadeOutControl], a; ld [wLowHealthAlarm], a */
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_LOW_HEALTH_ALARM] = 0;
	/* dec a -> 0xFF (SFX_STOP_ALL_MUSIC); ld [wNewSoundID], a; call PlaySound */
	memory[W_NEW_SOUND_ID] = SFX_STOP_ALL_MUSIC;
	state->a = SFX_STOP_ALL_MUSIC;
	port_play_sound(state, memory);

	/* call DelayFrame -- frame wait, no observable audio state. */

	/* Choose the battle music. */
	if (memory[W_GYM_LEADER_NO] != 0) {
		music_id = MUSIC_GYM_LEADER_BATTLE;
	} else {
		port_u8 opp = memory[W_CUR_OPPONENT];
		if (opp < OPP_ID_OFFSET) {
			music_id = MUSIC_WILD_BATTLE;
		} else if (opp == OPP_RIVAL3) {
			music_id = MUSIC_FINAL_BATTLE;
		} else if (opp == OPP_LANCE) {
			music_id = MUSIC_GYM_LEADER_BATTLE;
		} else {
			music_id = MUSIC_TRAINER_BATTLE;
		}
	}

	/* jp PlayMusic: set the audio banks and play the chosen song. */
	memory[W_NEW_SOUND_ID] = music_id;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
	memory[W_AUDIO_ROM_BANK] = bank;
	memory[W_AUDIO_SAVED_ROM_BANK] = bank;
	state->a = music_id;
	port_play_sound(state, memory);
}
