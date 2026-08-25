#include "port_state.h"
#include "joypad_port.h"

/* Port of the Joypad homecall wrapper in home/joypad.asm:
 *
 *   ldh a, [hLoadedROMBank]
 *   push af
 *   ld a, BANK(_Joypad)
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   call _Joypad
 *   pop af
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   ret
 *
 * Switches to the _Joypad bank, runs the proved joypad diff, and restores
 * the saved bank on both the HRAM mirror and the MBC register. The callee's
 * A/F are discarded by `pop af`, but its B/D/E scratch results survive:
 * E := previous [hJoyLast], D := last ^ input, and B := input, or
 * ~wJoyIgnore when the ignore mask applies. On the PAD_BUTTONS soft-reset
 * sentinel the modeled early return happens before any scratch clobber. */

void port_joypad(struct joypad_update_state *, port_u8 *);

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define JOYPAD_BANK 3u

__attribute__((noinline, used)) void
port_joypad_homecall(struct cpu_register_state *state, port_u8 *memory)
{
	struct joypad_update_state joy;
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->f;
	port_u8 input = memory[H_JOYINPUT];
	port_u8 last = memory[H_JOYLAST];
	port_u8 ignore = memory[W_JOYIGNORE];
	port_u8 disabled = memory[W_STATUSFLAGS5] &
	    (port_u8)(1u << BIT_DISABLE_JOYPAD);

	memory[H_LOADED_ROM_BANK] = JOYPAD_BANK;
	memory[R_ROMB] = JOYPAD_BANK;
	port_joypad(&joy, memory);

	if (input != PAD_BUTTONS)
	{
		state->e = last;
		state->d = (port_u8)(input ^ last);
		if (disabled == 0u && ignore != 0u)
			state->b = (port_u8)~ignore;
		else
			state->b = input;
	}
	state->a = saved_bank;
	state->f = saved_f;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
}
