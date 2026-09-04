#include "port_state.h"

void port_clear_sprites(struct clear_sprites_state *);
void port_delay_frame(struct delay_frame_state *, const port_u8 *);
void port_init_intro_nidorino_oam(struct init_intro_oam_state *, port_u8 *);
void port_intro_copy_tiles(struct cpu_register_state *);
void port_run_palette_command(struct cpu_register_state *, port_u8 *);
void port_intro_move_mon(struct cpu_register_state *, port_u8 *);


#define H_JOY_HELD 0xffb4u
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define H_SCX 0xffaeu


#define MOVE_NIDORINO_RIGHT 0xffu
#define MOVE_GENGAR_LEFT 1u
#define W_BASE_COORD_X 0xd081u
#define W_BASE_COORD_Y 0xd082u
#define W_INTRO_NIDORINO_BASE_TILE 0xd09fu
#define W_SHADOW_OAM 0xc300u
#define SHADOW_OAM_SIZE 1024u

void port_check_for_user_interruption(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);
void port_update_intro_nidorino_oam(struct intro_nidorino_oam_state *);

static void
intro_update_nidorino_oam(struct cpu_register_state *state, port_u8 *memory)
{
	struct intro_nidorino_oam_state oam;

	oam.registers = *state;
	oam.base_tile = memory[W_INTRO_NIDORINO_BASE_TILE];
	oam.base_y = memory[W_BASE_COORD_Y];
	oam.base_x = memory[W_BASE_COORD_X];
	for (unsigned i = 0; i < SHADOW_OAM_SIZE; ++i)
		oam.oam[i] = memory[W_SHADOW_OAM + i];
	oam.registers.c = 6u * 6u;
	port_update_intro_nidorino_oam(&oam);
	for (unsigned i = 0; i < SHADOW_OAM_SIZE; ++i)
		memory[W_SHADOW_OAM + i] = oam.oam[i];
	*state = oam.registers;
}

/* Port of AnimateIntroNidorino in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_animate_intro_nidorino(struct cpu_register_state *state,
	port_u8 *memory, const port_u8 *animation)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	const port_u8 *cursor = animation;

	for (;;) {
		port_u8 y = *cursor;

		state->a = y;
		if (y == 80u) {
			state->f = PORT_FLAG_Z | PORT_FLAG_N;
			return;
		}
		memory[W_BASE_COORD_Y] = y;
		cursor++;
		memory[W_BASE_COORD_X] = *cursor;
		state->a = memory[W_BASE_COORD_X];
		{
			port_u8 saved_d = state->d;
			port_u8 saved_e = state->e;

			intro_update_nidorino_oam(state, memory);
			state->d = saved_d;
			state->e = saved_e;
		}
		{
			struct delay_frame_state delay;
			port_u8 saved_d = state->d;
			port_u8 saved_e = state->e;

			delay.registers = *state;
			delay.registers.c = 5;
			port_delay_frames(&delay, acknowledged_vblank);
			*state = delay.registers;
			state->d = saved_d;
			state->e = saved_e;
		}
		cursor++;
		{
			port_u16 de = (port_u16)(((port_u16)state->d << 8) |
				state->e);
			de = (port_u16)(de + 2u);
			state->d = (port_u8)(de >> 8);
			state->e = (port_u8)de;
		}
	}
}

/* Port of IntroMoveMon in engine/movie/intro.asm. */
__attribute__((noinline, used)) void
port_intro_move_mon(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 direction = state->e;

	do {
		if (direction == MOVE_NIDORINO_RIGHT) {
			port_u8 saved_d = state->d;
			port_u8 saved_e = state->e;

			memory[W_BASE_COORD_X] = 2;
			memory[W_BASE_COORD_Y] = 0;
			intro_update_nidorino_oam(state, memory);
			state->d = saved_d;
			state->e = saved_e;
		}

		{
			port_u8 scx = memory[H_SCX];
			if (direction == MOVE_NIDORINO_RIGHT ||
			    direction == MOVE_GENGAR_LEFT)
				scx = (port_u8)(scx + 2u);
			else
				scx = (port_u8)(scx - 2u);
			memory[H_SCX] = scx;
		}

		{
			port_u8 saved_d = state->d;
			port_u8 saved_e = state->e;

			state->c = 2;
			port_check_for_user_interruption(state, memory);
			state->d = saved_d;
			state->e = saved_e;
		}
		if ((state->f & PORT_FLAG_C) != 0)
			return;

		{
			port_u8 before = state->d;
			port_u8 result = (port_u8)(before - 1u);
			port_u8 flags = (port_u8)(state->f & PORT_FLAG_C);

			if (result == 0)
				flags |= PORT_FLAG_Z;
			if ((before & 0x0fu) == 0)
				flags |= PORT_FLAG_H;
			flags |= PORT_FLAG_N;
			state->d = result;
			state->f = flags;
			if (result == 0)
				return;
		}
	} while (1);
}
/* PlayShootingStar and PlayIntroScene remain explicit call boundaries. */
__attribute__((noinline, used)) void
port_play_intro(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 observations[1] = {0};
	struct clear_sprites_state sprites = {0};
	struct delay_frame_state delay = {0};

	memory[H_JOY_HELD] = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;

	/* GBFadeOutToWhite is an explicit visual-effect boundary. */
	memory[H_SCX] = 0;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;

	sprites.registers = *state;
	port_clear_sprites(&sprites);
	*state = sprites.registers;

	delay.registers = *state;
	port_delay_frame(&delay, observations);
	*state = delay.registers;
}
/*
 * The scene port currently covers the setup and first-interruption path.
 * The remaining animation choreography stays outside this proof domain.
 */
__attribute__((noinline, used)) void
port_play_intro_scene(struct cpu_register_state *state, port_u8 *memory)
{
	struct init_intro_oam_state init;

	state->b = 7;
	port_run_palette_command(state, memory);
	state->a = 0xe4;
	memory[0xff47u] = state->a;
	memory[0xff48u] = state->a;
	memory[0xff49u] = state->a;
	state->a = 0;
	memory[H_SCX] = state->a;

	state->b = 3;
	port_intro_copy_tiles(state);
	state->a = 0;
	memory[W_BASE_COORD_X] = state->a;
	state->a = 80;
	memory[W_BASE_COORD_Y] = state->a;

	init.registers = *state;
	init.registers.b = 6;
	init.registers.c = 6;
	init.base_y = memory[W_BASE_COORD_Y];
	init.base_x = memory[W_BASE_COORD_X];
	port_init_intro_nidorino_oam(&init, memory);
	*state = init.registers;

	state->d = 40;
	state->e = MOVE_NIDORINO_RIGHT;
	port_intro_move_mon(state, memory);
}
