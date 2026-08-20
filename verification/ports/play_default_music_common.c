#include "port_state.h"

struct play_default_music_common_state {
    struct cpu_register_state registers;
    port_u8 surf_state;
    port_u8 map_music_sound;
    port_u8 map_music_bank;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 last_music_sound;
    port_u8 new_sound_id;
    port_u8 fade_control;
    port_u8 play_sound_called;
};

#define MUSIC_BIKE_RIDING 0xd2u
#define MUSIC_SURFING 0xd6u
#define BANK_MUSIC_BIKE_RIDING 0x1fu

/* Port of PlayDefaultMusicCommon in home/audio.asm. CompareMapMusicBank and
 * PlaySound are represented by explicit bank reconciliation and call state. */
__attribute__((noinline, used)) void
port_play_default_music_common(struct play_default_music_common_state *state)
{
    port_u8 music;
    if (state->surf_state == 0) {
        music = state->map_music_sound;
        if (state->audio_rom_bank != state->map_music_bank) {
            if (state->registers.c == 0)
                state->audio_rom_bank = state->map_music_bank;
            state->audio_saved_bank = state->map_music_bank;
        } else {
            state->audio_saved_bank = state->audio_rom_bank;
            if (state->last_music_sound == music)
                return;
        }
    } else {
        music = state->surf_state == 2 ? MUSIC_SURFING : MUSIC_BIKE_RIDING;
        if (state->registers.d == 0)
            state->audio_rom_bank = BANK_MUSIC_BIKE_RIDING;
        state->audio_saved_bank = BANK_MUSIC_BIKE_RIDING;
        if (state->last_music_sound == music)
            return;
    }
    state->fade_control = state->registers.c;
    state->last_music_sound = music;
    state->new_sound_id = music;
    state->registers.a = music;
    state->play_sound_called = 1;
}
