#include "port_state.h"

/* Port of PlayTrainerMusic in home/trainers.asm:
 *
 *   ld a, [wEngagedTrainerClass]
 *   cp OPP_RIVAL1 ($e1); ret z
 *   cp OPP_RIVAL2 ($f2); ret z
 *   cp OPP_RIVAL3 ($f3); ret z
 *   ld a, [wGymLeaderNo]
 *   and a
 *   ret nz
 *   xor a; ld [wAudioFadeOutControl], a
 *   ld a, SFX_STOP_ALL_MUSIC ($ff); call PlaySound
 *   ld a, BANK(Music_MeetEvilTrainer) ($1f)
 *   ld [wAudioROMBank], a; ld [wAudioSavedROMBank], a
 *   ld a, [wEngagedTrainerClass]; ld b, a
 *   ld hl, EvilTrainerList          ; d5 d9 dc dd e3 e4 e5 e6 ff
 * .evilTrainerListLoop:
 *   ld a, [hli]; cp $ff; jr z, .noEvilTrainer
 *   cp b; jr nz, .evilTrainerListLoop
 *   ld a, MUSIC_MEET_EVIL_TRAINER ($f6); jr .PlaySound
 * .noEvilTrainer:
 *   ld hl, FemaleTrainerList        ; cb ce da e8 ff
 * .femaleTrainerListLoop:
 *   ld a, [hli]; cp $ff; jr z, .maleTrainer
 *   cp b; jr nz, .femaleTrainerListLoop
 *   ld a, MUSIC_MEET_FEMALE_TRAINER ($f9); jr .PlaySound
 * .maleTrainer:
 *   ld a, MUSIC_MEET_MALE_TRAINER ($fc)
 * .PlaySound:
 *   ld [wNewSoundID], a
 *   jp PlaySound
 *
 * Both list tables are static ROM data, byte-verified in the test. The two
 * PlaySound invocations compose the proven PlaySound contract as arbitrary
 * matching transitions at their call sites.
 */

void port_play_sound(struct play_sound_state *);

#define W_ENGAGED_TRAINER_CLASS 0xcd2du
#define W_GYM_LEADER_NO         0xd05cu
#define W_AUDIO_FADE_OUT_CONTROL 0xcfc7u
#define W_AUDIO_ROM_BANK        0xc0efu
#define W_AUDIO_SAVED_ROM_BANK  0xc0f0u
#define W_NEW_SOUND_ID          0xc0eeu
#define RIVAL1 0xe1u
#define RIVAL2 0xf2u
#define RIVAL3 0xf3u
#define SFX_STOP_ALL_MUSIC 0xffu
#define SONG_EVIL   0xf6u
#define SONG_FEMALE 0xf9u
#define SONG_MALE   0xfcu

__attribute__((noinline, used)) void
port_play_trainer_music(struct cpu_register_state *state, port_u8 *memory)
{
	static const port_u8 evil_list[9] = {
	    0xd5, 0xd9, 0xdc, 0xdd, 0xe3, 0xe4, 0xe5, 0xe6,
	    0xff};
	static const port_u8 female_list[5] = {0xcb, 0xce, 0xda, 0xe8, 0xff};
	port_u16 hl;
	port_u8 class = memory[W_ENGAGED_TRAINER_CLASS];
	port_u8 song = SONG_MALE;
	port_u8 i;

	state->a = class;

	/* three rival checks: ret z keeps A = class, F = N|Z */
	if (class == RIVAL1 || class == RIVAL2 || class == RIVAL3) {
		state->f = (port_u8)(PORT_FLAG_N | PORT_FLAG_Z);
		return;
	}

	/* ld a,[wGymLeaderNo]; and a; ret nz (A = gym leader number) */
	state->a = memory[W_GYM_LEADER_NO];
	{
		port_u8 gym = state->a;
		state->f = (port_u8)(PORT_FLAG_H |
				     ((gym == 0) ? PORT_FLAG_Z : 0));
		if (gym != 0)
			return;
	}

	/* xor a; ld [wAudioFadeOutControl], a */
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_AUDIO_FADE_OUT_CONTROL] = 0;

	/* ld a, SFX_STOP_ALL_MUSIC; call PlaySound */
	state->a = SFX_STOP_ALL_MUSIC;
	{
		struct play_sound_state ps;
		ps.registers = *state;
		ps.new_sound_id = memory[W_NEW_SOUND_ID];
		ps.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
		ps.fade_control = memory[W_AUDIO_FADE_OUT_CONTROL];
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
		memory[W_NEW_SOUND_ID] = ps.new_sound_id;
		memory[W_AUDIO_FADE_OUT_CONTROL] = ps.fade_control;
	}

	/* ld a, BANK(Music_MeetEvilTrainer) ($1f); stores */
	state->a = 0x1fu;
	memory[W_AUDIO_ROM_BANK] = 0x1fu;
	memory[W_AUDIO_SAVED_ROM_BANK] = 0x1fu;

	/* ld a, [wEngagedTrainerClass]; ld b, a */
	class = memory[W_ENGAGED_TRAINER_CLASS];
	state->a = class;
	state->b = class;

	port_u8 f;

	hl = 0x3439u; /* ld hl, EvilTrainerList */
	for (i = 0;; i++) {
		port_u8 entry = evil_list[i];
		state->a = entry;
		hl++;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;

		/* cp $ff: N set, Z iff terminator, H iff low nibble < $f. */
		state->f = (port_u8)(PORT_FLAG_N |
				     ((entry & 0x0fu) < 0x0fu ? PORT_FLAG_H : 0) |
				     ((entry == 0xffu) ? PORT_FLAG_Z : 0));
		if (entry == 0xffu)
			break; /* jr z, .noEvilTrainer */

		/* cp b */
		f = PORT_FLAG_N;
		if (class == entry)
			f |= PORT_FLAG_Z;
		if ((class & 0x0fu) < (entry & 0x0fu))
			f |= PORT_FLAG_H;
		if (class < entry)
			f |= PORT_FLAG_C;
		state->f = f;
		if (class == entry) {
			song = SONG_EVIL;
			goto play;
		}
	}

	hl = 0x3434u; /* ld hl, FemaleTrainerList */
	for (i = 0;; i++) {
		port_u8 entry = female_list[i];
		state->a = entry;
		hl++;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;

		state->f = (port_u8)(PORT_FLAG_N |
				     ((entry & 0x0fu) < 0x0fu ? PORT_FLAG_H : 0) |
				     ((entry == 0xffu) ? PORT_FLAG_Z : 0));
		if (entry == 0xffu)
			break; /* jr z, .maleTrainer */

		f = PORT_FLAG_N;
		if (class == entry)
			f |= PORT_FLAG_Z;
		if ((class & 0x0fu) < (entry & 0x0fu))
			f |= PORT_FLAG_H;
		if (class < entry)
			f |= PORT_FLAG_C;
		state->f = f;
		if (class == entry) {
			song = SONG_FEMALE;
			goto play;
		}
	}

play:
	/* .PlaySound: ld [wNewSoundID], a; jp PlaySound (tail) */
	state->a = song;
	memory[W_NEW_SOUND_ID] = song;
	{
		struct play_sound_state ps;
		ps.registers = *state;
		ps.new_sound_id = memory[W_NEW_SOUND_ID];
		ps.audio_rom_bank = memory[W_AUDIO_ROM_BANK];
		ps.fade_control = memory[W_AUDIO_FADE_OUT_CONTROL];
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
		memory[W_NEW_SOUND_ID] = ps.new_sound_id;
		memory[W_AUDIO_FADE_OUT_CONTROL] = ps.fade_control;
	}
}
