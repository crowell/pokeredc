#include "port_state.h"

#define H_CURRENT_SPRITE_OFFSET 0xffdau

static void
add_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 previous = registers->a;
	port_u16 result = (port_u16)previous + value;

	registers->a = (port_u8)result;
	registers->f = (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) + (value & 0x0fu) > 0x0fu
			? PORT_FLAG_H : 0)
		| (result > 0xffu ? PORT_FLAG_C : 0);
}

/* Port of GetSpriteScreenXYPointerCommon in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_get_sprite_screen_xy_pointer_common(struct cpu_register_state *registers,
	port_u8 *memory)
{
	registers->h = 0xc1;
	registers->l = 0;
	registers->a = memory[H_CURRENT_SPRITE_OFFSET];
	add_a(registers, registers->l);
	add_a(registers, registers->b);
	registers->l = registers->a;
}
