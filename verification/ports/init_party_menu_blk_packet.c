#include "port_state.h"

/* Port of InitPartyMenuBlkPacket in engine/gfx/palettes.asm.
 *
 * ld hl, $62f4; ld de, $cf2e; ld bc, $0030; jp $00b5.
 * The setup instructions preserve F; the tail jp is the path boundary. */

#define INIT_PARTY_MENU_BLK_PACKET_HL 0x62f4u
#define INIT_PARTY_MENU_BLK_PACKET_DE 0xcf2eu
#define INIT_PARTY_MENU_BLK_PACKET_BC 0x0030u

__attribute__((noinline, used)) void
port_init_party_menu_blk_packet(struct cpu_register_state *state, port_u8 *memory)
{
    (void)memory;
    state->h = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_HL >> 8);
    state->l = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_HL & 0xff);
    state->d = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_DE >> 8);
    state->e = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_DE & 0xff);
    state->b = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_BC >> 8);
    state->c = (port_u8)(INIT_PARTY_MENU_BLK_PACKET_BC & 0xff);
}
