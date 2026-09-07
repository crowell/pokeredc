#include "port_state.h"

void port_call_function_in_table(struct call_function_table_state *,
	port_u8, port_u8);
void port_run_npc_movement_script_player_step_out_from_door(
	struct cpu_register_state *, port_u8 *);

#define W_NPC_MOVEMENT_SCRIPT_POINTER_TABLE_NUM 0xcc57u
#define W_NPC_MOVEMENT_SCRIPT_BANK 0xcc58u
#define W_NPC_MOVEMENT_SCRIPT_FUNCTION_NUM 0xcf10u
#define W_MOVEMENT_FLAGS 0xd736u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

static const port_u16 movement_script_pointer_tables[] = {
	0x6442u, 0x6510u, 0x657du,
};

static void
bit_zero_at_hl(struct cpu_register_state *r, port_u8 value)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((value & 1u) == 0)
		r->f |= PORT_FLAG_Z;
}

static void
and_a(struct cpu_register_state *r)
{
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
}

static void
dec_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u8 carry = r->f & PORT_FLAG_C;

	r->a--;
	r->f = (port_u8)(carry | PORT_FLAG_N);
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((old & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

static void
add_a(struct cpu_register_state *r)
{
	port_u8 old = r->a;
	port_u16 result = (port_u16)old + old;

	r->a = (port_u8)result;
	r->f = 0;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((old & 0x0fu) + (old & 0x0fu) > 0x0fu)
		r->f |= PORT_FLAG_H;
	if (result > 0xffu)
		r->f |= PORT_FLAG_C;
}

static void
add_hl_de(struct cpu_register_state *r)
{
	port_u16 left = (port_u16)(((port_u16)r->h << 8) | r->l);
	port_u16 right = (port_u16)(((port_u16)r->d << 8) | r->e);
	unsigned long result = (unsigned long)left + right;
	port_u8 flags = r->f & PORT_FLAG_Z;

	if ((left & 0x0fffu) + (right & 0x0fffu) > 0x0fffu)
		flags |= PORT_FLAG_H;
	if (result > 0xffffu)
		flags |= PORT_FLAG_C;
	r->f = flags;
	r->h = (port_u8)(result >> 8);
	r->l = (port_u8)result;
}

/* Port of RunNPCMovementScript in home/npc_movement.asm.
 * fetched_low/high are the two bytes read by the proven indirect dispatcher
 * from the selected banked movement-script table. */
__attribute__((noinline, used)) void
port_run_npc_movement_script(struct cpu_register_state *r, port_u8 *memory,
	port_u8 fetched_low, port_u8 fetched_high,
	port_u8 callback_a, port_u8 callback_f)
{
	struct call_function_table_state call;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u16 table;

	r->h = (port_u8)(W_MOVEMENT_FLAGS >> 8);
	r->l = (port_u8)W_MOVEMENT_FLAGS;
	bit_zero_at_hl(r, memory[W_MOVEMENT_FLAGS]);
	memory[W_MOVEMENT_FLAGS] &= (port_u8)~1u;
	if ((r->f & PORT_FLAG_Z) == 0) {
		port_run_npc_movement_script_player_step_out_from_door(r, memory);
		return;
	}

	r->a = memory[W_NPC_MOVEMENT_SCRIPT_POINTER_TABLE_NUM];
	and_a(r);
	if (r->a == 0)
		return;
	dec_a(r);
	add_a(r);
	r->d = 0;
	r->e = r->a;
	r->h = 0x31;
	r->l = 0x40;
	add_hl_de(r);
	table = movement_script_pointer_tables[
		memory[W_NPC_MOVEMENT_SCRIPT_POINTER_TABLE_NUM] - 1u];
	r->a = (port_u8)table;
	{
		port_u16 hl = (port_u16)(((port_u16)r->h << 8) | r->l) + 1u;
		r->h = (port_u8)(hl >> 8);
		r->l = (port_u8)hl;
	}
	r->h = (port_u8)(table >> 8);
	r->l = r->a;
	r->a = memory[H_LOADED_ROM_BANK];
	saved_a = r->a;
	saved_f = r->f;
	r->a = memory[W_NPC_MOVEMENT_SCRIPT_BANK];
	memory[H_LOADED_ROM_BANK] = r->a;
	memory[R_ROMB] = r->a;
	r->a = memory[W_NPC_MOVEMENT_SCRIPT_FUNCTION_NUM];
	call.registers = *r;
	call.fetched_low = fetched_low;
	call.fetched_high = fetched_high;
	port_call_function_in_table(&call, callback_a, callback_f);
	*r = call.registers;
	r->a = saved_a;
	r->f = saved_f;
	memory[H_LOADED_ROM_BANK] = r->a;
	memory[R_ROMB] = r->a;
}
