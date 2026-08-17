#include "port_state.h"

/*
 * Port of PrintText in home/window.asm:
 *
 *   push hl
 *   ld a, MESSAGE_BOX
 *   ld [wTextBoxID], a
 *   call DisplayTextBoxID   ; no observable memory effect
 *   call UpdateSprites      ; no observable memory effect
 *   call Delay3             ; no observable memory effect
 *   pop hl
 * PrintText_NoCreatingTextBox:
 *   bccoord 1, 14
 *   jp TextCommandProcessor
 *
 * The only observable write of PrintText's own body is wTextBoxID = MESSAGE_BOX.
 * The actual text rendering is performed by TextCommandProcessor, which is the
 * tail continuation: it receives HL (the text pointer, restored from the stack)
 * and BC = the (1, 14) box coordinate. Both are set up here.
 */

#define W_TEXT_BOX_ID 0xd125
#define MESSAGE_BOX   0x01
#define SCREEN_WIDTH  20
#define W_TILE_MAP    0xc3a0

__attribute__((noinline, used)) void
port_print_text(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_TEXT_BOX_ID] = MESSAGE_BOX;

	/* PrintText_NoCreatingTextBox: bccoord 1, 14 (continuation input). */
	{
		port_u16 box = (port_u16)(W_TILE_MAP + 14 * SCREEN_WIDTH + 1);
		state->b = (port_u8)(box >> 8);
		state->c = (port_u8)box;
	}
	/* HL still holds the text pointer; TextCommandProcessor is the tail. */
}
