#include "port_state.h"

/* Port of Random_ in engine/math/random.asm. */
__attribute__((noinline, used)) void
port_random(struct random_state *state)
{
	port_u8 left;
	port_u8 right;
	port_u8 carry;
	port_u16 wide;

	state->registers.a = state->div_first;
	state->registers.b = state->registers.a;
	state->registers.a = state->random_add;
	left = state->registers.a;
	right = state->registers.b;
	carry = (state->registers.f & PORT_FLAG_C) != 0;
	wide = (port_u16)left + right + carry;
	state->registers.a = (port_u8)wide;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) + carry > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->random_add = state->registers.a;
	state->registers.a = state->div_second;
	state->registers.b = state->registers.a;
	state->registers.a = state->random_sub;
	left = state->registers.a;
	right = state->registers.b;
	carry = (state->registers.f & PORT_FLAG_C) != 0;
	wide = (port_u16)right + carry;
	state->registers.a = (port_u8)(left - wide);
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f) + carry)
		state->registers.f |= PORT_FLAG_H;
	if ((port_u16)left < wide)
		state->registers.f |= PORT_FLAG_C;
	state->random_sub = state->registers.a;
}

/* Port of Random in home/random.asm.
 *
 * Generates a random number by calling Random_, then returns the updated
 * hRandomAdd value in A.
 *
 * Input: none
 * Output: A = random value (updated hRandomAdd), other registers preserved */

#define H_RANDOM_ADD 0xFFD3u
#define H_RANDOM_SUB 0xFFD4u
#define R_DIV 0xFF04u

/* Forward declaration of the Random_ port. */
__attribute__((noinline, used)) void
port_random(struct random_state *state);

__attribute__((noinline, used)) void
port_random_generate(struct cpu_register_state *state, port_u8 *memory)
{
	/* Build the random_state from current CPU state and memory. */
	struct random_state rand_state = {0};

	/* rDIV is read twice by Random_. We need two independent samples. */
	rand_state.div_first = memory[R_DIV];
	rand_state.div_second = memory[R_DIV];

	/* Current random state from memory. */
	rand_state.random_add = memory[H_RANDOM_ADD];
	rand_state.random_sub = memory[H_RANDOM_SUB];

	/* Copy general registers. */
	rand_state.registers = *state;

	/* Call the Random_ port. */
	port_random(&rand_state);

	/* Random returns the updated hRandomAdd in A. */
	state->a = rand_state.random_add;

	/* Update memory with the new random state. */
	memory[H_RANDOM_ADD] = rand_state.random_add;
	memory[H_RANDOM_SUB] = rand_state.random_sub;
}