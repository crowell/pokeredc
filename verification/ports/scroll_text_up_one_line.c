#include "port_state.h"

/* Port of ScrollTextUpOneLine in home/text.asm:
 *
 *   hlcoord 0, 14          ; HL := $c4b8 (top row of the text box)
 *   decoord 0, 13          ; DE := $c4a4 (empty line above)
 *   ld b, SCREEN_WIDTH * 3
 * .copyText:
 *   ld a, [hli] / ld [de], a / inc de / dec b / jr nz, .copyText
 *   hlcoord 1, 16          ; HL := $c4e1
 *   ld a, ' ' / ld b, SCREEN_WIDTH - 2
 * .clearText:
 *   ld [hli], a / dec b / jr nz, .clearText
 *   ld b, 5
 * .WaitFrame:
 *   call DelayFrame / dec b / jr nz, .WaitFrame
 *   ret
 *
 * The forward 60-byte copy moves the bottom three text rows up one row
 * (DE < HL so the overlapping forward copy never clobbers unread source),
 * the second input row is cleared to spaces, and five proved DelayFrame
 * waits pace the scroll to the frame update. */

void port_delay_frame(struct delay_frame_state *, const port_u8 *);

#define W_TILE_MAP 0xc3a0u
#define SCROLL_COPY_SIZE 60u
#define SCROLL_CLEAR_SIZE 18u
#define TILE_SPACE 0x7fu
#define SCROLL_FRAMES 5u

static const port_u8 acknowledged_vblank[] = { 0 };

__attribute__((noinline, used)) void
port_scroll_text_up_one_line(struct cpu_register_state *state,
	port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	port_u16 hl = W_TILE_MAP + 14u * 20u;
	port_u16 de = W_TILE_MAP + 13u * 20u;
	port_u8 b;

	for (b = SCROLL_COPY_SIZE; b != 0u; b--)
	{
		memory[de++] = memory[hl++];
	}

	hl = W_TILE_MAP + 16u * 20u + 1u;
	for (b = SCROLL_CLEAR_SIZE; b != 0u; b--)
	{
		memory[hl++] = TILE_SPACE;
	}

	for (b = SCROLL_FRAMES; b != 0u; b--)
	{
		struct delay_frame_state delay;

		delay.registers = *state;
		delay.vblank_occurred = 0;
		delay.observed_vblank = 0;
		port_delay_frame(&delay, acknowledged_vblank);
		state->a = delay.registers.a;
		state->f = delay.registers.f;
	}

	/* The final `dec b` (1 -> 0) supplies the exit flags: Z set, N set,
	 * no half-borrow, and the carry preserved from DelayFrame (zero). */
	state->f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);
	state->b = 0u;
	state->c = entry.c;
	state->d = (port_u8)((W_TILE_MAP + 13u * 20u + SCROLL_COPY_SIZE) >> 8);
	state->e = (port_u8)((W_TILE_MAP + 13u * 20u + SCROLL_COPY_SIZE) &
	    0xffu);
	state->h = (port_u8)((W_TILE_MAP + 16u * 20u + 1u + SCROLL_CLEAR_SIZE) >>
	    8);
	state->l = (port_u8)((W_TILE_MAP + 16u * 20u + 1u + SCROLL_CLEAR_SIZE) &
	    0xffu);
}
