#include "port_state.h"

#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

/* The bank-1 implementation is kept as an explicit seam until its sprite
 * iteration is ported.  The wrapper below still models the complete homecall
 * register and bank-register contract.
 */
__attribute__((noinline, used)) void
port_update_sprites_private(struct cpu_register_state *registers,
	port_u8 *memory)
{
	(void)registers;
	(void)memory;
	__asm__ volatile("" ::: "memory");
}

/* Port of UpdateSprites in home/update_sprites.asm. */
__attribute__((noinline, used)) void
port_update_sprites(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u8 before = memory[W_UPDATE_SPRITES_ENABLED];
	port_u8 value = (port_u8)(before - 1);
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 saved_bank;

	registers->a = value;
	registers->f = (port_u8)(registers->f & PORT_FLAG_C);
	registers->f |= PORT_FLAG_N;
	if (value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
	if (value != 0)
		return;

	saved_a = memory[H_LOADED_ROM_BANK];
	saved_f = registers->f;
	saved_bank = memory[H_LOADED_ROM_BANK];
	registers->a = 1;
	memory[H_LOADED_ROM_BANK] = 1;
	memory[R_ROMB] = 1;
	port_update_sprites_private(registers, memory);
	registers->a = saved_a;
	registers->f = saved_f;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_a;
}
