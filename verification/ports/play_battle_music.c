#include "port_state.h"

struct play_battle_music_state {
    struct cpu_register_state registers;
    port_u8 gym_leader_no;
    port_u8 cur_opponent;
    port_u8 fade_control;
    port_u8 low_health_alarm;
    port_u8 sound_id;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 stop_sound_called;
    port_u8 delay_frame_called;
    port_u8 play_music_called;
};

#define MUSIC_GYM_LEADER_BATTLE 0xeau
#define MUSIC_TRAINER_BATTLE 0xedu
#define MUSIC_WILD_BATTLE 0xf0u
#define MUSIC_FINAL_BATTLE 0xf3u
#define SFX_STOP_ALL_MUSIC 0xffu
#define BANK_MUSIC_GYM_LEADER_BATTLE 0x08u
#define OPP_ID_OFFSET 200u
#define OPP_RIVAL3 243u
#define OPP_LANCE 247u

/* Port of PlayBattleMusic in audio/play_battle_music.asm. PlaySound,
 * DelayFrame, and PlayMusic are represented by explicit call-boundary state. */
__attribute__((noinline, used)) void
port_play_battle_music(struct play_battle_music_state *state)
{
    port_u8 music_id;
    state->fade_control = 0;
    state->low_health_alarm = 0;
    state->sound_id = SFX_STOP_ALL_MUSIC;
    state->stop_sound_called = 1;
    state->delay_frame_called = 1;
    if (state->gym_leader_no != 0) {
        music_id = MUSIC_GYM_LEADER_BATTLE;
    } else if (state->cur_opponent < OPP_ID_OFFSET) {
        music_id = MUSIC_WILD_BATTLE;
    } else if (state->cur_opponent == OPP_RIVAL3) {
        music_id = MUSIC_FINAL_BATTLE;
    } else if (state->cur_opponent == OPP_LANCE) {
        music_id = MUSIC_GYM_LEADER_BATTLE;
    } else {
        music_id = MUSIC_TRAINER_BATTLE;
    }
    state->sound_id = music_id;
    state->audio_rom_bank = BANK_MUSIC_GYM_LEADER_BATTLE;
    state->audio_saved_bank = BANK_MUSIC_GYM_LEADER_BATTLE;
    state->play_music_called = 1;
    state->registers.a = music_id;
}
