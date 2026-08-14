#include "port_state.h"

/* Port of ResetPlayerSpriteData_ClearSpriteData in home/reset_player_sprite.asm.
 *
 * Sets BC to the sprite-state length, zeroes A (XOR A), then tail-jumps to
 * FillMemory to zero the caller-provided HL buffer. */
void port_fill_memory(struct fill_memory_state *state, port_u8 *memory);

#define SPRITE_STATE_LENGTH 0x10

__attribute__((noinline, used)) void
port_reset_player_sprite_data_clear_sprite_data(
	struct cpu_register_state *state, port_u8 *memory)
{
	state->b = 0;
	state->c = SPRITE_STATE_LENGTH;
	state->a = 0;
	state->f = PORT_FLAG_Z;
	{
		struct fill_memory_state fms;
		fms.registers = *state;
		port_fill_memory(&fms, memory);
		*state = fms.registers;
	}
}
