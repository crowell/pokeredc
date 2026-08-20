#include "port_state.h"

struct load_front_sprite_by_mon_index_state {
    struct cpu_register_state registers;
    port_u8 saved_pokedex_num;
    port_u8 dex_number;
    port_u8 pokedex_num;
    port_u8 cur_party_species;
    port_u8 start_tile_id;
    port_u8 sprite_flipped;
    port_u8 load_front_sprite_called;
    port_u8 copy_pic_called;
    port_u8 loaded_rom_bank;
    port_u8 saved_rom_bank;
    port_u8 rom_bank;
};

#define NUM_POKEMON 151u
#define RHYDON 1u

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
    port_u8 f = PORT_FLAG_N;
    if (left == right) f |= PORT_FLAG_Z;
    if ((left & 0x0f) < (right & 0x0f)) f |= PORT_FLAG_H;
    if (left < right) f |= PORT_FLAG_C;
    return f;
}

/* Port of LoadFrontSpriteByMonIndex in home/pokemon.asm. IndexToPokedex,
 * LoadMonFrontSprite, and CopyUncompressedPicToHL are explicit boundaries. */
__attribute__((noinline, used)) void
port_load_front_sprite_by_mon_index(
    struct load_front_sprite_by_mon_index_state *state)
{
    state->pokedex_num = state->saved_pokedex_num;
    if (state->dex_number == 0) {
        state->cur_party_species = RHYDON;
        state->registers.a = RHYDON;
        state->registers.f = PORT_FLAG_H | PORT_FLAG_Z;
        return;
    }
    if (state->dex_number > NUM_POKEMON) {
        state->cur_party_species = RHYDON;
        state->registers.a = RHYDON;
        state->registers.f = cp_flags(state->dex_number, NUM_POKEMON + 1);
        return;
    }
    state->load_front_sprite_called = 1;
    state->start_tile_id = 0;
    state->copy_pic_called = 1;
    state->sprite_flipped = 0;
    state->registers.a = 0;
    state->registers.f = PORT_FLAG_Z;
}
