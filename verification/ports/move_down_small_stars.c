#include "port_state.h"

#define H_MOVE_DOWN_SMALL_STARS_OAM_COUNT 0xcd3du
#define R_OBP1 0xff49u
#define W_SHADOW_OAM 0xc300u
#define W_SHADOW_OAM_SPRITE23 (W_SHADOW_OAM + 23u * 4u)
#define OBJ_SIZE 4u
#define SMALL_STAR_PALETTE_MASK 0xa0u

void port_check_for_user_interruption(struct cpu_register_state *, port_u8 *);

/* Port of MoveDownSmallStars in engine/movie/splash.asm. */
__attribute__((noinline, used)) void
port_move_down_small_stars(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 outer_count = 8;

	state->b = outer_count;
	do {
		port_u16 cursor = W_SHADOW_OAM_SPRITE23;
		port_u8 inner_count = memory[H_MOVE_DOWN_SMALL_STARS_OAM_COUNT];

		state->h = (port_u8)(cursor >> 8);
		state->l = (port_u8)cursor;
		state->d = 0xff;
		state->e = 0xfc;
		state->a = inner_count;
		state->c = inner_count;

		do {
			memory[cursor]++;
			cursor = (port_u16)(cursor - OBJ_SIZE);
			inner_count--;
		} while (inner_count != 0);

		state->h = (port_u8)(cursor >> 8);
		state->l = (port_u8)cursor;
		state->c = 0;
		state->a = memory[R_OBP1];
		state->a ^= SMALL_STAR_PALETTE_MASK;
		state->f = state->a == 0 ? PORT_FLAG_Z : 0;
		memory[R_OBP1] = state->a;

		{
			state->c = 3;
			port_u8 saved_b = state->b;
			port_u8 saved_c = state->c;

			port_check_for_user_interruption(state, memory);
			state->b = saved_b;
			state->c = saved_c;
		}
		if ((state->f & PORT_FLAG_C) != 0)
			return;

		outer_count--;
		state->b = outer_count;
		state->f = PORT_FLAG_N;
		if (outer_count == 0)
			state->f |= PORT_FLAG_Z;
	} while (outer_count != 0);
}
