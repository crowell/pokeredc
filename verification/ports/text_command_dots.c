#include "port_state.h"
#include "joypad_port.h"

/* Port of TextCommand_DOTS in home/text.asm (the TX_DOTS handler):
 *
 *   pop hl                  ; the dispatcher's pushed text pointer
 *   ld a, [hli] / ld d, a   ; D := dot count, HL := past the count byte
 *   push hl                 ; save the text pointer
 *   ld h, b / ld l, c       ; HL := wTextDest (B:C)
 * .loop
 *   ld a, '…' / ld [hli], a ; write the ellipsis tile, advance dest
 *   push de / call Joypad / pop de
 *   ldh a, [hJoyHeld] / and PAD_A | PAD_B
 *   jr nz, .next            ; skip the delay if a button is held
 *   ld c, 10 / call DelayFrames
 * .next
 *   dec d / jr nz, .loop
 *   ld b, h / ld c, l       ; B:C := the destination end
 *   pop hl                  ; restore the text pointer
 *   jp NextTextCommand      ; the dispatcher's loop
 *
 * Writes `count` ellipsis tiles into the destination window, polling the
 * joypad each iteration and delaying ten frames unless a button is held.
 * The Joypad and DelayFrames calls compose through the proved
 * port_joypad_homecall and port_delay_frames transitions; the HL entry is
 * the dispatcher's pushed text pointer and the continuation into
 * NextTextCommand composes through the dispatcher proof. */

void port_joypad_homecall(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

#define TILE_ELLIPSIS 0x75u
#define DOTS_DELAY_FRAMES 10u

static const port_u8 acknowledged_vblank[] = { 0 };

__attribute__((noinline, used)) void
port_text_command_dots(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 entry_e = state->e;
	port_u16 text_ptr = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u8 count = memory[text_ptr];
	port_u16 saved_text_ptr = (port_u16)(text_ptr + 1u); /* past the count */
	port_u16 dest = (port_u16)(((port_u16)state->b << 8) | state->c);

	do {
		memory[dest] = TILE_ELLIPSIS;            /* ld [hli], a */
		dest = (port_u16)(dest + 1u);

		port_u8 save_d = state->d, save_e = state->e;
		port_joypad_homecall(state, memory);      /* push de / call / pop de */
		state->d = save_d;
		state->e = save_e;

		state->a = (port_u8)(memory[H_JOYHELD] & (PAD_A | PAD_B));
		state->f = PORT_FLAG_H;
		if (state->a == 0u)
			state->f |= PORT_FLAG_Z;
		if (state->a != 0u)
			goto next;                       /* jr nz, .next */

		{
			struct delay_frame_state delay;

			state->c = DOTS_DELAY_FRAMES;
			delay.registers = *state;
			delay.vblank_occurred = 0;
			delay.observed_vblank = 0;
			port_delay_frames(&delay, acknowledged_vblank);
			*state = delay.registers;
		}
	next:
		count = (port_u8)(count - 1u);
	} while (count != 0u);

	/* The final `dec d` leaves D = 0, so the SM83 flags are Z and N set
	 * (H and C clear), matching the assembly's terminal flag state. */
	state->f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);

	/* The final `dec d` leaves D = 0; E is never modified. */
	state->b = (port_u8)(dest >> 8);
	state->c = (port_u8)dest;
	state->d = 0u;
	state->e = entry_e;
	state->h = (port_u8)(saved_text_ptr >> 8);
	state->l = (port_u8)saved_text_ptr;
}
