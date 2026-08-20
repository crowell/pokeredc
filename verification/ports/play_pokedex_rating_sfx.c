#include "port_state.h"

struct play_pokedex_rating_sfx_state {
    struct cpu_register_state registers;
    port_u8 num_mons_owned;
    port_u8 new_sound_id;
    port_u8 audio_fade_out_control;
    port_u8 audio_rom_bank;
    port_u8 audio_saved_bank;
    port_u8 last_music_sound_id;
    port_u8 stop_sound_called;
    port_u8 rating_sound_called;
    port_u8 default_music_called;
};

/* Port of PlayPokedexRatingSfx in audio/pokedex_rating_sfx.asm. The two
 * PlaySound calls and PlayDefaultMusic fallthrough are explicit boundaries. */
__attribute__((noinline, used)) void
port_play_pokedex_rating_sfx(struct play_pokedex_rating_sfx_state *state)
{
    port_u8 id, bank;
    if (state->num_mons_owned < 10) { id=0xa5; bank=0x1f; }
    else if (state->num_mons_owned < 40) { id=0x91; bank=2; }
    else if (state->num_mons_owned < 60) { id=0x86; bank=2; }
    else if (state->num_mons_owned < 90) { id=0x9a; bank=8; }
    else if (state->num_mons_owned < 120) { id=0x86; bank=8; }
    else if (state->num_mons_owned < 150) { id=0x94; bank=2; }
    else { id=0x89; bank=2; }
    state->stop_sound_called = 1;
    state->new_sound_id = id;
    state->audio_fade_out_control = 0;
    state->audio_rom_bank = bank;
    state->audio_saved_bank = bank;
    state->rating_sound_called = 1;
    state->last_music_sound_id = 0;
    state->default_music_called = 1;
    state->registers.a = id;
}
