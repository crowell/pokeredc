#include "port_state.h"

/* Port of WriteMonPartySpriteOAM.makeCopy in engine/gfx/mon_icons.asm.
 *
 * ld hl, $c300; ld de, $cc5b; ld bc, $0060; jp $00b5.
 * The setup instructions preserve F; the local CopyData JP is the boundary. */

#define WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_HL 0xc300u
#define WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_DE 0xcc5bu
#define WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_BC 0x0060u

__attribute__((noinline, used)) void
port_write_mon_party_sprite_oam_make_copy(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_HL >> 8);
    state->l = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_HL & 0xff);
    state->d = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_DE >> 8);
    state->e = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_DE & 0xff);
    state->b = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_BC >> 8);
    state->c = (port_u8)(WRITE_MON_PARTY_SPRITE_OAM_MAKE_COPY_BC & 0xff);
}
