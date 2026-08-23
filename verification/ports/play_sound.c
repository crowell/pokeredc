#include "port_state.h"

/* Port of PlaySound in home/audio.asm. AudioX_PlaySound is represented by
 * dispatch_called; all dispatcher bookkeeping remains explicit state. */
__attribute__((noinline, used)) void
port_play_sound(struct play_sound_state *state)
{
    port_u8 sound = state->registers.a;
    if (state->new_sound_id != 0)
        for (int i = 0; i < 4; i++) state->channel_sound_ids[i] = 0;
    if (state->fade_control != 0) {
        if (state->new_sound_id == 0)
            return;
        state->new_sound_id = 0;
        if (state->last_music_sound_id != 0xff) {
            state->last_music_sound_id = sound;
            state->fade_reload = state->fade_control;
            state->fade_counter = state->fade_control;
            state->fade_control = sound;
            return;
        }
        state->fade_control = 0;
    }
    state->new_sound_id = 0;
    state->saved_rom_bank = state->loaded_rom_bank;
    state->loaded_rom_bank = state->audio_rom_bank;
    state->rom_bank = state->audio_rom_bank;
    state->dispatch_called = 1;
    state->loaded_rom_bank = state->saved_rom_bank;
    state->rom_bank = state->saved_rom_bank;
}
