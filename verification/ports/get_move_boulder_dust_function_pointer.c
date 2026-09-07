#include "port_state.h"

#define W_PLAYER_FACING 0xc109u
#define W_COORD_ADJUSTMENT_AMOUNT 0xd08au
#define W_SHADOW_OAM_SPRITE36 0xc390u

static port_u16
get_hl(const struct cpu_register_state *registers)
{
	return (port_u16)(((port_u16)registers->h << 8) | registers->l);
}

static port_u16
get_bc(const struct cpu_register_state *registers)
{
	return (port_u16)(((port_u16)registers->b << 8) | registers->c);
}

static port_u16
get_de(const struct cpu_register_state *registers)
{
	return (port_u16)(((port_u16)registers->d << 8) | registers->e);
}

static void
set_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

static void
add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = get_hl(registers);
	port_u32 result = (port_u32)left + right;

	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fffu) + (right & 0x0fffu) > 0x0fffu)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffffu)
		registers->f |= PORT_FLAG_C;
	set_hl(registers, (port_u16)result);
}

/* Port of GetMoveBoulderDustFunctionPointer in
 * engine/overworld/dust_smoke.asm. */
__attribute__((noinline, used)) void
port_get_move_boulder_dust_function_pointer_memory(
	struct cpu_register_state *registers, port_u8 *memory,
	const port_u8 *pointer_table)
{
	port_u16 table_index;
	port_u16 function;

	registers->a = memory[W_PLAYER_FACING];
	set_hl(registers, 0x5fb0u);
	registers->c = registers->a;
	registers->b = 0;
	add_hl(registers, get_bc(registers));
	table_index = registers->c;

	registers->a = pointer_table[table_index++];
	memory[W_COORD_ADJUSTMENT_AMOUNT] = registers->a;
	registers->a = pointer_table[table_index++];
	registers->e = registers->a;
	registers->a = pointer_table[table_index++];
	function = (port_u16)(registers->a |
		((port_u16)pointer_table[table_index] << 8));
	set_hl(registers, function);

	set_hl(registers, W_SHADOW_OAM_SPRITE36);
	registers->d = 0;
	add_hl(registers, get_de(registers));
	registers->e = registers->l;
	registers->d = registers->h;
	set_hl(registers, function);
}
