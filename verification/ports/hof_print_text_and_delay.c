#include "port_state.h"

/* Port of HoFPrintTextAndDelay in engine/movie/hall_of_fame.asm:
 *
 *   call PrintText
 *   ld c, 120
 *   jp DelayFrames
 *
 * Composition of two proven ports: PrintText at its called entry, then a
 * faithful 120-frame DelayFrames bridge.
 */

void port_print_text(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

#define DELAY_COUNT 0x78u /* 120 frames */

__attribute__((noinline, used)) void
port_hof_print_text_and_delay(struct cpu_register_state *state,
			      port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	/* call PrintText */
	port_print_text(state, memory);

	/* ld c, 120; jp DelayFrames */
	state->c = DELAY_COUNT;
	delay.registers = *state;
	delay.vblank_occurred = memory[0xffd6]; /* hVBlankOccurred input */
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*state = delay.registers;
	memory[0xffd6] = delay.vblank_occurred;
}
