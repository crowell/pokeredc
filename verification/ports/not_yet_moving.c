#include "port_state.h"

#define W_SPRITE_STATE_DATA1 0xc100u
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define SPRITESTATEDATA1_ANIMFRAMECOUNTER 8u

/* Port of NotYetMoving (engine/overworld/movement.asm).
 *
 * Writes 0 to the sprite's ANIMFRAMECOUNTER field, then jumps to
 * UpdateSpriteImage (separate, modeled tail). The direct observable is the
 * zero write; the jp UpdateSpriteImage is an explicit boundary. The address is
 * fixed at HIGH(wSpriteStateData1) with LOW = (hCurrentSpriteOffset + 8),
 * matching the 8-bit add (no carry into the high byte). */
__attribute__((noinline, used)) void
port_not_yet_moving(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 offset = memory[H_CURRENT_SPRITE_OFFSET];
	port_u16 addr = (port_u16)(W_SPRITE_STATE_DATA1 +
		((port_u16)offset + SPRITESTATEDATA1_ANIMFRAMECOUNTER) % 0x100u);
	memory[addr] = 0;
}
