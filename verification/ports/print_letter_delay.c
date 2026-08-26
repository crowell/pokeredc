#include "port_state.h"
#include "joypad_port.h"

/* Port of PrintLetterDelay in home/print_text.asm:
 *
 *   ld a, [wStatusFlags5] / bit BIT_NO_TEXT_DELAY, a / ret nz
 *   ld a, [wLetterPrintingDelayFlags] / bit BIT_TEXT_DELAY, a / ret z
 *   push hl / push de / push bc
 *   ld a, [wLetterPrintingDelayFlags] / bit BIT_FAST_TEXT_DELAY, a
 *   jr z, .waitOneFrame
 *   ld a, [wOptions] / and $f / ldh [hFrameCounter], a
 *   jr .checkButtons
 * .waitOneFrame:
 *   ld a, 1 / ldh [hFrameCounter], a
 * .checkButtons:
 *   call Joypad / ldh a, [hJoyHeld]
 *   bit B_PAD_A, a / jr z, .checkBButton / jr .endWait
 * .checkBButton:
 *   bit B_PAD_B, a / jr z, .buttonsNotPressed
 * .endWait:
 *   call DelayFrame / jr .done
 * .buttonsNotPressed:
 *   ldh a, [hFrameCounter] / and a / jr nz, .checkButtons
 * .done:
 *   pop bc / pop de / pop hl / ret
 *
 * The poll spin (`jr nz, .checkButtons`) is driven by the external VBlank
 * ISR decrementing hFrameCounter between polls. With the ISR out of proof
 * scope the non-terminating spin is an explicit boundary (the established
 * text-poll precedent), and this port carries the terminating observations. */
#define H_FRAME_COUNTER 0xffd5u
#define W_LETTER_PRINTING_DELAY_FLAGS 0xd358u
#define W_OPTIONS 0xd355u
#define BIT_NO_TEXT_DELAY 7u
#define BIT_TEXT_DELAY 1u
#define BIT_FAST_TEXT_DELAY 0u

void port_joypad_homecall(struct cpu_register_state *, port_u8 *);
void port_delay_frame(struct delay_frame_state *, const port_u8 *);


static const port_u8 acknowledged_vblank[] = { 0 };

__attribute__((noinline, used)) void
port_print_letter_delay(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	port_u8 a = memory[W_STATUSFLAGS5];

	if ((a & (port_u8)(1u << BIT_NO_TEXT_DELAY)) != 0u)
	{
		state->a = a;
		state->f = (port_u8)((entry.f & PORT_FLAG_C) | PORT_FLAG_H |
		    ((a & (port_u8)(1u << BIT_NO_TEXT_DELAY)) != 0u ?
		    0u : PORT_FLAG_Z));
		return;
	}
	a = memory[W_LETTER_PRINTING_DELAY_FLAGS];
	if ((a & (port_u8)(1u << BIT_TEXT_DELAY)) == 0u)
	{
		state->a = a;
		state->f = (port_u8)((entry.f & PORT_FLAG_C) | PORT_FLAG_H |
		    ((a & (port_u8)(1u << BIT_TEXT_DELAY)) != 0u ?
		    0u : PORT_FLAG_Z));
		return;
	}

	memory[H_FRAME_COUNTER] =
	    (a & (port_u8)(1u << BIT_FAST_TEXT_DELAY)) != 0u ?
	    (port_u8)(memory[W_OPTIONS] & 0x0fu) : 1u;

	port_joypad_homecall(state, memory);
	a = memory[H_JOYHELD];
	if ((a & (port_u8)(PAD_A | PAD_B)) != 0u)
	{
		struct delay_frame_state delay;

		delay.registers = *state;
		delay.vblank_occurred = 0;
		delay.observed_vblank = 0;
		port_delay_frame(&delay, acknowledged_vblank);
		*state = delay.registers;
	}
	else
	{
		/* The poll spin repeats the identical cycle until the external
		 * VBlank ISR drives hFrameCounter to zero, then falls through to
		 * the same `and a`/done observation with the counter at zero. */
		memory[H_FRAME_COUNTER] = 0u;
		state->a = 0u;
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
	}
	state->b = entry.b;
	state->c = entry.c;
	state->d = entry.d;
	state->e = entry.e;
	state->h = entry.h;
	state->l = entry.l;
}
