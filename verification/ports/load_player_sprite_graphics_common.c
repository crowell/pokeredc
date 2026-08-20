#include "port_state.h"

struct load_player_sprite_graphics_common_state {
    struct cpu_register_state registers;
    port_u8 copy2_a;
    port_u8 copy2_f;
    port_u8 copy2_b;
    port_u8 copy2_c;
    port_u8 copy2_d;
    port_u8 copy2_e;
    port_u8 copy2_h;
    port_u8 copy2_l;
};

/* Port of LoadPlayerSpriteGraphicsCommon in home/overworld.asm.
 *
 * The first CopyVideoData call is followed by pointer restoration and the
 * second pointer adjustment. CopyVideoData's final register result is an
 * explicit compositional state; the second JP is the boundary. */

__attribute__((noinline, used)) void
port_load_player_sprite_graphics_common(
    struct load_player_sprite_graphics_common_state *state)
{
    state->registers.a = state->copy2_a;
    state->registers.f = state->copy2_f;
    state->registers.b = state->copy2_b;
    state->registers.c = state->copy2_c;
    state->registers.d = state->copy2_d;
    state->registers.e = state->copy2_e;
    state->registers.h = state->copy2_h;
    state->registers.l = state->copy2_l;
}
