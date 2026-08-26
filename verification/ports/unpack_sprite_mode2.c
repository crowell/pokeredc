#include "port_state.h"

#define W_SPRITE_LOAD_FLAGS 0xd0a9u
#define W_SPRITE_FLIPPED 0xd0aau
#define W_SPRITE_OUTPUT_PTR 0xd0adu
#define W_SPRITE_OUTPUT_PTR_CACHED 0xd0afu

void port_reset_sprite_buffer_pointers(struct register_memory_state *);
void port_sprite_differential_decode(struct cpu_register_state *, port_u8 *);
void port_xor_sprite_chunks(struct cpu_register_state *, port_u8 *);

static void
unpack_mode2_reset_pointers(struct cpu_register_state *state, port_u8 *memory)
{
	struct register_memory_state reset;

	reset.registers = *state;
	reset.memory[0] = memory[W_SPRITE_LOAD_FLAGS];
	reset.memory[1] = memory[W_SPRITE_OUTPUT_PTR];
	reset.memory[2] = memory[W_SPRITE_OUTPUT_PTR + 1];
	reset.memory[3] = memory[W_SPRITE_OUTPUT_PTR_CACHED];
	reset.memory[4] = memory[W_SPRITE_OUTPUT_PTR_CACHED + 1];
	port_reset_sprite_buffer_pointers(&reset);
	*state = reset.registers;
	memory[W_SPRITE_OUTPUT_PTR] = reset.memory[1];
	memory[W_SPRITE_OUTPUT_PTR + 1] = reset.memory[2];
	memory[W_SPRITE_OUTPUT_PTR_CACHED] = reset.memory[3];
	memory[W_SPRITE_OUTPUT_PTR_CACHED + 1] = reset.memory[4];
}

/* Port of UnpackSpriteMode2 in home/uncompress.asm. */
__attribute__((noinline, used)) void
port_unpack_sprite_mode2(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_a;
	port_u8 saved_f;

	unpack_mode2_reset_pointers(state, memory);
	state->a = memory[W_SPRITE_FLIPPED];
	saved_a = state->a;
	saved_f = state->f;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	memory[W_SPRITE_FLIPPED] = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR_CACHED];
	state->l = state->a;
	state->a = memory[W_SPRITE_OUTPUT_PTR_CACHED + 1];
	state->h = state->a;
	port_sprite_differential_decode(state, memory);
	unpack_mode2_reset_pointers(state, memory);
	state->a = saved_a;
	state->f = saved_f;
	memory[W_SPRITE_FLIPPED] = state->a;
	port_xor_sprite_chunks(state, memory);
}
