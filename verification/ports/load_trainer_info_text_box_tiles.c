#include "port_state.h"

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

/* Port of LoadTrainerInfoTextBoxTiles in engine/link/cable_club.asm. */

#define LTIT_DE 0x7b98u
#define LTIT_B  0x0bu
#define LTIT_C  0x09u

__attribute__((noinline, used)) void
port_load_trainer_info_text_box_tiles(
    struct cpu_register_state *state, port_u8 *memory)
{
    state->d = (port_u8)(LTIT_DE >> 8);
    state->e = (port_u8)(LTIT_DE & 0xff);
    state->h = (port_u8)(0x9760u >> 8);
    state->l = (port_u8)(0x9760u & 0xff);
    state->b = LTIT_B;
    state->c = LTIT_C;
    port_copy_video_data(state, memory);
}
