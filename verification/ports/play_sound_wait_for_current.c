#include "port_state.h"

/* Port of PlaySoundWaitForCurrent in home/delay.asm.
 *
 * Waits for any currently playing sound to finish, then plays the sound
 * whose ID is in A. The A register and flags are preserved across the wait.
 *
 * Input: A = sound ID to play after waiting
 * Output: A, F from PlaySound */

#define PLAY_SOUND_ADDR 0x23B1u

/* Forward declarations. */
__attribute__((noinline, used)) void
port_wait_for_sound_to_finish(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_play_music(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_play_sound_wait_for_current(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;

	/* Save A and F (push af) */
	port_u8 saved_a = state->a;
	port_u8 saved_f = state->f;

	/* Call WaitForSoundToFinish */
	port_wait_for_sound_to_finish(state, memory);

	/* Restore A and F (pop af) */
	state->a = saved_a;
	state->f = saved_f;

	/* Tail-call PlaySound */
	port_play_music(state, memory);
}