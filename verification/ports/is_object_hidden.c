#include "port_state.h"

#define W_TOGGLEABLE_OBJECT_FLAGS 0xd5a6u
#define W_TOGGLEABLE_OBJECT_LIST 0xd5ceu
#define H_CURRENT_SPRITE_OFFSET 0xffdau
#define H_IS_TOGGLEABLE_OBJECT_OFF 0xffe5u

void port_toggleable_object_flag_action(struct flag_action_state *);

static void
cp_a(struct cpu_register_state *r, port_u8 value)
{
	port_u8 left = r->a;

	r->f = PORT_FLAG_N;
	if (left == value)
		r->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (value & 0x0fu))
		r->f |= PORT_FLAG_H;
	if (left < value)
		r->f |= PORT_FLAG_C;
}

static void
and_a(struct cpu_register_state *r)
{
	r->f = PORT_FLAG_H;
	if (r->a == 0)
		r->f |= PORT_FLAG_Z;
}

/* Port of IsObjectHidden in engine/overworld/toggleable_objects.asm. */
__attribute__((noinline, used)) void
port_is_object_hidden(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 hl = W_TOGGLEABLE_OBJECT_LIST;
	r->a = memory[H_CURRENT_SPRITE_OFFSET];
	r->a = (port_u8)((r->a << 4) | (r->a >> 4));
	r->f = r->a == 0 ? PORT_FLAG_Z : 0;
	r->b = r->a;
	r->h = (port_u8)(hl >> 8);
	r->l = (port_u8)hl;
	for (;;) {
		r->a = memory[hl++];
		r->h = (port_u8)(hl >> 8);
		r->l = (port_u8)hl;
		cp_a(r, 0xffu);
		if (r->f & PORT_FLAG_Z)
			goto not_hidden;
		cp_a(r, r->b);
		r->a = memory[hl++];
		r->h = (port_u8)(hl >> 8);
		r->l = (port_u8)hl;
		if (!(r->f & PORT_FLAG_Z))
			continue;
		r->c = r->a;
		r->b = 2;
		r->h = (port_u8)(W_TOGGLEABLE_OBJECT_FLAGS >> 8);
		r->l = (port_u8)W_TOGGLEABLE_OBJECT_FLAGS;
		{
			struct flag_action_state action;
			port_u16 flag_byte = (port_u16)(W_TOGGLEABLE_OBJECT_FLAGS + (r->c >> 3));

			action.registers = *r;
			action.value = memory[flag_byte];
			port_toggleable_object_flag_action(&action);
			*r = action.registers;
			memory[flag_byte] = action.value;
		}
		r->a = r->c;
		and_a(r);
		if (r->a != 0)
			break;
not_hidden:
		r->a = 0;
		r->f = PORT_FLAG_Z;
		break;
	}
	memory[H_IS_TOGGLEABLE_OBJECT_OFF] = r->a;
}
