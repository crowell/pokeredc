#include "port_state.h"

#define W_SPRITE_PLAYER_IMAGE_INDEX 0xc102u
#define W_SPRITE_PLAYER_Y_PIXELS 0xc104u
#define W_FACING_DIRECTION_LIST 0xcd48u
#define W_SAVED_PLAYER_SCREEN_Y 0xcd4fu
#define W_SAVED_PLAYER_FACING_DIRECTION 0xcd50u
#define PLAYER_SPINNING_FACING_ORDER 0x4713u

void port_copy_data(struct cpu_register_state *, port_u8 *);

static void
compare_a_at_hl(struct cpu_register_state *registers, const port_u8 *memory)
{
	port_u8 value = memory[((port_u16)registers->h << 8) | registers->l];
	port_u8 previous = registers->a;

	registers->f = PORT_FLAG_N | (previous == value ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) < (value & 0x0fu) ? PORT_FLAG_H : 0)
		| (previous < value ? PORT_FLAG_C : 0);
}

/* Port of InitFacingDirectionList in engine/overworld/player_animations.asm. */
__attribute__((noinline, used)) void
port_init_facing_direction_list(struct cpu_register_state *registers,
	port_u8 *memory)
{
	registers->a = memory[W_SPRITE_PLAYER_IMAGE_INDEX];
	memory[W_SAVED_PLAYER_FACING_DIRECTION] = registers->a;
	registers->a = memory[W_SPRITE_PLAYER_Y_PIXELS];
	memory[W_SAVED_PLAYER_SCREEN_Y] = registers->a;
	registers->h = (port_u8)(PLAYER_SPINNING_FACING_ORDER >> 8);
	registers->l = (port_u8)PLAYER_SPINNING_FACING_ORDER;
	registers->d = (port_u8)(W_FACING_DIRECTION_LIST >> 8);
	registers->e = (port_u8)W_FACING_DIRECTION_LIST;
	registers->b = 0;
	registers->c = 4;
	port_copy_data(registers, memory);
	registers->a = memory[W_SPRITE_PLAYER_IMAGE_INDEX];
	registers->h = (port_u8)(W_FACING_DIRECTION_LIST >> 8);
	registers->l = (port_u8)W_FACING_DIRECTION_LIST;
	do {
		compare_a_at_hl(registers, memory);
		registers->l++;
	} while (!(registers->f & PORT_FLAG_Z));
	registers->l--;
}
