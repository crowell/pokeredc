#include "port_state.h"

#define PARTY_LENGTH 6u
#define MONS_PER_BOX 20u

/* Port of _GivePokemon in engine/events/give_pokemon.asm. AddPartyMon,
 * SendNewMonToBox, and text rendering are explicit call-boundary state. */
__attribute__((noinline, used)) void
port_give_pokemon(struct give_pokemon_state *state)
{
    state->added_to_party = 0;
    if (state->party_count < PARTY_LENGTH) {
        state->added_to_party = 1;
        state->do_not_wait = 1;
        state->add_party_mon_called = 1;
        state->registers.f = PORT_FLAG_C;
        return;
    }
    if (state->box_count >= MONS_PER_BOX) {
        state->registers.f = 0;
        return;
    }
    state->enemy_battle_status3 = 0;
    state->enemy_mon_species2 = state->cur_party_species;
    state->send_to_box_called = 1;
    port_u8 box = state->current_box_num & 0x7f;
    if (box >= 9) {
        state->string_buffer[0] = '1';
        state->string_buffer[1] = (port_u8)((box - 9) + '0');
        state->string_buffer[2] = '@';
    } else {
        state->string_buffer[0] = (port_u8)(box + '1');
        state->string_buffer[1] = '@';
        state->string_buffer[2] = 0;
    }
    state->registers.f = PORT_FLAG_C;
}
