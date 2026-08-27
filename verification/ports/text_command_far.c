#include "port_state.h"

/* Port of TextCommand_FAR in home/text.asm.
 *
 *   pop hl                       ; discard (caller's return)
 *   ldh a, [hLoadedROMBank]
 *   push af                      ; save current bank
 *   ld a, [hli] / e              ; far pointer low
 *   ld a, [hli] / d              ; far pointer high
 *   ld a, [hli] / bank           ; target bank
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   push hl                      ; save ptr past the 3-byte arg
 *   ld l, e / ld h, d
 *   call TextCommandProcessor    ; recurse (proved compositional boundary)
 *   pop hl                       ; restore ptr past the 3-byte arg
 *   pop af                       ; restore bank
 *   ldh [hLoadedROMBank], a
 *   ld [rROMB], a
 *   jp NextTextCommand
 *
 * In the C port the return address is the C call frame, so we keep HL as the
 * far pointer source, load the 3-byte argument, switch banks, recurse into
 * port_text_command_processor (boundary), then restore HL to just past the
 * 3-byte argument and restore the bank. */

#define H_LOADED_ROM_BANK 0xFFB8u
#define R_ROMB 0x2000u

void port_text_command_processor(struct cpu_register_state *,
				 port_u8 *);

__attribute__((noinline, used)) void
port_text_command_far(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 ptr = (port_u16)((port_u16)(state->h << 8) | state->l);
	port_u8 old_bank = memory[H_LOADED_ROM_BANK];
	port_u8 ptr_low = memory[ptr];
	port_u8 ptr_high = memory[ptr + 1u];
	port_u8 bank = memory[ptr + 2u];

	memory[H_LOADED_ROM_BANK] = bank;
	memory[R_ROMB] = bank;

	port_u16 far_ptr =
		(port_u16)((port_u16)(ptr_high << 8) | ptr_low);
	state->h = (port_u8)(far_ptr >> 8);
	state->l = (port_u8)far_ptr;

	port_text_command_processor(state, memory);

	port_u16 after = (port_u16)(ptr + 3u);
	state->h = (port_u8)(after >> 8);
	state->l = (port_u8)after;

	memory[H_LOADED_ROM_BANK] = old_bank;
	memory[R_ROMB] = old_bank;
}
