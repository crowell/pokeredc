#include "port_state.h"

struct not_yet_moving_state {
    struct cpu_register_state registers;
    port_u8 sprite_offset;
    port_u8 anim_frame;
};

#define ANIM_FRAME_OFFSET 0x08u
#define SPRITE_STATE_HIGH 0xc1u

/* Port of NotYetMoving in engine/overworld/movement.asm.
 *
 * ld h,$c1; ldh a,[hCurrentSpriteOffset]; add $08; ld l,a;
 * ld [hl],$00; jp UpdateSpriteImage. Explicit state replaces raw WRAM/I/O addresses. */

__attribute__((noinline, used)) void
port_not_yet_moving(struct not_yet_moving_state *state)
{
    port_u8 input = state->sprite_offset;
    port_u16 result = (port_u16)input + ANIM_FRAME_OFFSET;
    port_u8 flags = 0;
    if ((port_u8)result == 0)
        flags |= PORT_FLAG_Z;
    if ((input & 0x0f) + ANIM_FRAME_OFFSET > 0x0f)
        flags |= PORT_FLAG_H;
    if (result > 0xff)
        flags |= PORT_FLAG_C;
    state->registers.h = SPRITE_STATE_HIGH;
    state->registers.a = (port_u8)result;
    state->registers.f = flags;
    state->registers.l = (port_u8)result;
    state->anim_frame = 0;
}
