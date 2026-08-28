#include "joypad_port.h"

#define W_ENTERING_CABLE_CLUB 0xcc47u

void port_wait_for_text_scroll_button_press(struct wait_for_text_scroll_state *);

/* Port of AfterDisplayingTextID in home/text_script.asm.
 *
 * The following HoldTextDisplayOpen/CloseTextDisplay sequence is a shared
 * fall-through continuation.  This entry faithfully selects the cable-club
 * skip or the ordinary text-scroll wait, then returns at that continuation
 * boundary.  The wait transition is composed through the proven port with
 * the caller's register values as the documented continuation state.
 */
__attribute__((noinline, used)) void
port_after_displaying_text_id(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 entering = memory[W_ENTERING_CABLE_CLUB];
	registers->a = entering;
	registers->f = PORT_FLAG_H;
	if (entering == 0u)
	{
		struct wait_for_text_scroll_state wait;
		wait.registers = *registers;
		wait.down_arrow_blink1 = memory[H_DOWNARROWBLINK1];
		wait.down_arrow_blink2 = memory[H_DOWNARROWBLINK2];
		wait.joy5 = memory[H_JOY5];
		wait.wait_b = registers->b;
		wait.wait_c = registers->c;
		wait.wait_d = registers->d;
		wait.wait_e = registers->e;
		wait.wait_h = registers->h;
		wait.wait_l = registers->l;
		port_wait_for_text_scroll_button_press(&wait);
		*registers = wait.registers;
		memory[H_DOWNARROWBLINK1] = wait.down_arrow_blink1;
		memory[H_DOWNARROWBLINK2] = wait.down_arrow_blink2;
		registers->f |= PORT_FLAG_Z;
	}
}
