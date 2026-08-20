#include "port_state.h"

struct set_debug_new_game_party_state {
    struct cpu_register_state registers;
    port_u8 party_count;
    port_u8 party_species[6];
    port_u8 cur_party_species;
    port_u8 cur_enemy_level;
};

/* Port of SetDebugNewGameParty in engine/debug/debug_party.asm. AddPartyMon
 * is represented by its observable party-count/species append. */
__attribute__((noinline, used)) void
port_set_debug_new_game_party(struct set_debug_new_game_party_state *state)
{
    if (state->party_count == 0) {
        state->party_species[0] = 0x0a; state->party_species[1] = 0x15;
        state->party_species[2] = 0x14; state->party_species[3] = 0x68;
        state->party_species[4] = 0x76; state->party_count = 6;
    } else if (state->party_count == 1) {
        state->party_species[1] = 0x0a; state->party_species[2] = 0x15;
        state->party_species[3] = 0x14; state->party_species[4] = 0x68;
        state->party_species[5] = 0x76; state->party_count = 6;
    } else if (state->party_count == 2) {
        state->party_species[2] = 0x0a; state->party_species[3] = 0x15;
        state->party_species[4] = 0x14; state->party_species[5] = 0x68;
        state->party_count = 6;
    } else if (state->party_count == 3) {
        state->party_species[3] = 0x0a; state->party_species[4] = 0x15;
        state->party_species[5] = 0x14; state->party_count = 6;
    } else if (state->party_count == 4) {
        state->party_species[4] = 0x0a; state->party_species[5] = 0x15;
        state->party_count = 6;
    } else if (state->party_count == 5) {
        state->party_species[5] = 0x0a; state->party_count = 6;
    }
    state->cur_party_species = 0x76;
    state->cur_enemy_level = 57;
}
