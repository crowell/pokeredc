#include "port_state.h"

struct init_battle_common_state {
    struct cpu_register_state registers;
    port_u8 letter_printing_delay_flags;
    port_u8 enemy_mon_species2;
    port_u8 trainer_class;
    port_u8 ai_count;
    port_u8 enemy_mon_party_pos;
    port_u8 is_in_battle;
    port_u8 start_tile_id;
    port_u8 init_battle_variables_called;
    port_u8 init_wild_battle_called;
    port_u8 trainer_information_called;
    port_u8 init_battle_common_called;
};

#define OPP_ID_OFFSET 200u
#define BIT_TEXT_DELAY 1u

/* Port of InitBattleCommon in engine/battle/core.asm. The callfar/predef/
 * battle-transition boundaries are represented by explicit call state. */
__attribute__((noinline, used)) void
port_init_battle_common(struct init_battle_common_state *state)
{
    state->letter_printing_delay_flags &= (port_u8)~(1u << BIT_TEXT_DELAY);
    state->init_battle_variables_called = 1;
    if (state->enemy_mon_species2 < OPP_ID_OFFSET) {
        state->init_wild_battle_called = 1;
        state->is_in_battle = 1;
        return;
    }
    state->trainer_class = (port_u8)(state->enemy_mon_species2 - OPP_ID_OFFSET);
    state->trainer_information_called = 1;
    state->enemy_mon_species2 = 0;
    state->start_tile_id = 0;
    state->ai_count = 0xff;
    state->enemy_mon_party_pos = 0xff;
    state->is_in_battle = 2;
    state->init_battle_common_called = 1;
}
