#include "port_state.h"

struct music_poke_flute_in_battle_state {
    struct cpu_register_state registers;
    port_u16 channel5_pointer;
    port_u16 channel6_pointer;
    port_u16 channel7_pointer;
    port_u8 sound_called;
};

#define SFX_CAUGHT_MON 0x9au
#define POKE_FLUTE_CH5 0x6322u
#define POKE_FLUTE_CH6 0x6325u
#define POKE_FLUTE_CH7 0x449bu
#define CHANNEL_POINTER_END 0xc014u

/* Port of Music_PokeFluteInBattle in audio/poke_flute.asm. The
 * PlaySoundWaitForCurrent and Audio2_OverwriteChannelPointer calls are
 * represented by their explicit sound/pointer state effects. */
__attribute__((noinline, used)) void
port_music_poke_flute_in_battle(struct music_poke_flute_in_battle_state *state)
{
    state->registers.a = SFX_CAUGHT_MON;
    state->sound_called = 1;
    state->channel5_pointer = POKE_FLUTE_CH5;
    state->channel6_pointer = POKE_FLUTE_CH6;
    state->channel7_pointer = POKE_FLUTE_CH7;
    state->registers.a = (port_u8)(POKE_FLUTE_CH7 >> 8);
    state->registers.h = (port_u8)(CHANNEL_POINTER_END >> 8);
    state->registers.l = (port_u8)CHANNEL_POINTER_END;
}
