#include "port_state.h"

/* Port of CopyTempPicToMonPic.next in engine/battle/animations.asm.
 *
 * ld de, $c6e8; ld bc, $0031; jp $1848.
 * The setup instructions preserve F; the local video-copy JP is the boundary. */

#define COPY_TEMP_PIC_TO_MON_PIC_NEXT_DE 0xc6e8u
#define COPY_TEMP_PIC_TO_MON_PIC_NEXT_BC 0x0031u

__attribute__((noinline, used)) void
port_copy_temp_pic_to_mon_pic_next(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->d = (port_u8)(COPY_TEMP_PIC_TO_MON_PIC_NEXT_DE >> 8);
    state->e = (port_u8)(COPY_TEMP_PIC_TO_MON_PIC_NEXT_DE & 0xff);
    state->b = (port_u8)(COPY_TEMP_PIC_TO_MON_PIC_NEXT_BC >> 8);
    state->c = (port_u8)(COPY_TEMP_PIC_TO_MON_PIC_NEXT_BC & 0xff);
}
