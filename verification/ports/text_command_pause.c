#include "port_state.h"
#include "joypad_port.h"

/* Port of TextCommand_PAUSE in home/text.asm (the TX_PAUSE handler):
 *
 *   push bc
 *   call Joypad
 *   ldh a, [hJoyHeld]
 *   and PAD_A | PAD_B
 *   jr nz, .done
 *   ld c, 30
 *   call DelayFrames
 * .done:
 *   pop bc / pop hl / jp NextTextCommand
 *
 * Waits for a button or half a second. The pops restore the dispatcher's
 * saved BC and pushed text pointer (modeled as the entry BC/HL); the
 * continuation into NextTextCommand is the caller's loop and composes
 * through the dispatcher proof. */

void port_joypad_homecall(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static const port_u8 acknowledged_vblank[] = { 0 };

__attribute__((noinline, used)) void
port_text_command_pause(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;

	port_joypad_homecall(state, memory);
	state->a = (port_u8)(memory[H_JOYHELD] & (port_u8)(PAD_A | PAD_B));
	/* SM83 AND n sets H, clears C/N, and derives Z from the result. */
	state->f = PORT_FLAG_H;
	if (state->a == 0u)
		state->f |= PORT_FLAG_Z;
	if (state->a == 0u)
	{
		struct delay_frame_state delay;

		state->c = 30u;
		delay.registers = *state;
		delay.vblank_occurred = 0;
		delay.observed_vblank = 0;
		port_delay_frames(&delay, acknowledged_vblank);
		*state = delay.registers;
	}
	state->b = entry.b;
	state->c = entry.c;
	state->h = entry.h;
	state->l = entry.l;
}
