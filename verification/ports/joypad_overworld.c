#include "port_state.h"

typedef void (*map_script_callback)(struct cpu_register_state *, port_u8 *);

void port_run_map_script(struct cpu_register_state *, port_u8 *,
	port_u8, port_u8, port_u8, port_u8, map_script_callback);
void port_joypad_homecall(struct cpu_register_state *, port_u8 *);

#define W_PLAYER_Y_STEP_VECTOR 0xc103u
#define W_PLAYER_X_STEP_VECTOR 0xc105u
#define W_SIMULATED_JOYPAD_STATES_END 0xccd3u
#define W_SIMULATED_JOYPAD_STATES_INDEX 0xcd38u
#define W_UNUSED_OVERRIDE_SIMULATED_INDEX 0xcd3au
#define W_OVERRIDE_SIMULATED_MASK 0xcd3bu
#define W_JOY_IGNORE 0xcd6bu
#define W_STATUS_FLAGS5 0xd730u
#define W_STATUS_FLAGS7 0xd733u
#define W_MOVEMENT_FLAGS 0xd736u
#define W_CUR_MAP 0xd35eu
#define H_JOY_RELEASED 0xffb2u
#define H_JOY_PRESSED 0xffb3u
#define H_JOY_HELD 0xffb4u

#define ROUTE_17 0x1cu
#define PAD_DOWN 0x80u
#define PAD_CTRL_AND_BUTTONS 0xf3u

static void
bit_value(struct cpu_register_state *r, port_u8 value, unsigned bit)
{
	r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_H);
	if ((value & (port_u8)(1u << bit)) == 0)
		r->f |= PORT_FLAG_Z;
}

static void
and_value(struct cpu_register_state *r, port_u8 value)
{
	r->a &= value;
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

static void
cp_value(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;
	port_u8 result = (port_u8)(left - value);

	r->f = PORT_FLAG_N;
	if (result == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < value)
		r->f |= PORT_FLAG_C;
}

static void
dec_at_hl(struct cpu_register_state *r, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = r->f & PORT_FLAG_C;

	(*value)--;
	r->f = (port_u8)(carry | PORT_FLAG_N);
	if (*value == 0)
		r->f |= PORT_FLAG_Z;
	if ((old & 0x0fu) == 0)
		r->f |= PORT_FLAG_H;
}

static void
add_l(struct cpu_register_state *r)
{
	port_u8 left = r->a;
	port_u8 right = r->l;
	port_u16 result = (port_u16)left + right;

	r->a = (port_u8)result;
	r->f = 0;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) + (right & 0x0fu) > 0x0fu)
		r->f |= PORT_FLAG_H;
	if (result > 0xffu)
		r->f |= PORT_FLAG_C;
}

static void
inc_h(struct cpu_register_state *r)
{
	port_u8 old = r->h;
	port_u8 carry = r->f & PORT_FLAG_C;

	r->h++;
	r->f = carry;
	if (r->h == 0)
		r->f |= PORT_FLAG_Z;
	if ((old & 0x0fu) == 0x0fu)
		r->f |= PORT_FLAG_H;
}

/* Port of JoypadOverworld in home/overworld.asm. */
__attribute__((noinline, used)) void
port_joypad_overworld(struct cpu_register_state *r, port_u8 *memory,
	port_u8 npc_fetched_low, port_u8 npc_fetched_high,
	port_u8 npc_callback_a, port_u8 npc_callback_f,
	map_script_callback callback)
{
	port_u16 pointer;

	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[W_PLAYER_Y_STEP_VECTOR] = 0;
	memory[W_PLAYER_X_STEP_VECTOR] = 0;
	port_run_map_script(r, memory, npc_fetched_low, npc_fetched_high,
		npc_callback_a, npc_callback_f, callback);
	port_joypad_homecall(r, memory);
	r->a = memory[W_STATUS_FLAGS7];
	bit_value(r, r->a, 3);
	if ((r->f & PORT_FLAG_Z) != 0) {
		r->a = memory[W_CUR_MAP];
		cp_value(r, ROUTE_17);
		if ((r->f & PORT_FLAG_Z) != 0) {
			r->a = memory[H_JOY_HELD];
			and_value(r, PAD_CTRL_AND_BUTTONS);
			if ((r->f & PORT_FLAG_Z) != 0) {
				r->a = PAD_DOWN;
				memory[H_JOY_HELD] = r->a;
			}
		}
	}
	r->a = memory[W_STATUS_FLAGS5];
	bit_value(r, r->a, 7);
	if ((r->f & PORT_FLAG_Z) != 0)
		return;
	r->a = memory[H_JOY_HELD];
	r->b = r->a;
	r->a = memory[W_OVERRIDE_SIMULATED_MASK];
	and_value(r, r->b);
	if ((r->f & PORT_FLAG_Z) == 0)
		return;
	r->h = (port_u8)(W_SIMULATED_JOYPAD_STATES_INDEX >> 8);
	r->l = (port_u8)W_SIMULATED_JOYPAD_STATES_INDEX;
	dec_at_hl(r, &memory[W_SIMULATED_JOYPAD_STATES_INDEX]);
	r->a = memory[W_SIMULATED_JOYPAD_STATES_INDEX];
	cp_value(r, 0xffu);
	if ((r->f & PORT_FLAG_Z) != 0) {
		r->a = 0;
		r->f = PORT_FLAG_Z;
		memory[W_UNUSED_OVERRIDE_SIMULATED_INDEX] = 0;
		memory[W_SIMULATED_JOYPAD_STATES_INDEX] = 0;
		memory[W_SIMULATED_JOYPAD_STATES_END] = 0;
		memory[W_JOY_IGNORE] = 0;
		memory[H_JOY_HELD] = 0;
		r->h = (port_u8)(W_MOVEMENT_FLAGS >> 8);
		r->l = (port_u8)W_MOVEMENT_FLAGS;
		r->a = memory[W_MOVEMENT_FLAGS];
		and_value(r, 0xf8u);
		memory[W_MOVEMENT_FLAGS] = r->a;
		r->h = (port_u8)(W_STATUS_FLAGS5 >> 8);
		r->l = (port_u8)W_STATUS_FLAGS5;
		memory[W_STATUS_FLAGS5] &= 0x7fu;
		return;
	}
	r->h = (port_u8)(W_SIMULATED_JOYPAD_STATES_END >> 8);
	r->l = (port_u8)W_SIMULATED_JOYPAD_STATES_END;
	add_l(r);
	r->l = r->a;
	if ((r->f & PORT_FLAG_C) != 0)
		inc_h(r);
	pointer = (port_u16)(((port_u16)r->h << 8) | r->l);
	r->a = memory[pointer];
	memory[H_JOY_HELD] = r->a;
	and_value(r, r->a);
	if ((r->f & PORT_FLAG_Z) == 0)
		return;
	memory[H_JOY_PRESSED] = r->a;
	memory[H_JOY_RELEASED] = r->a;
}
