#include "port_state.h"

#define H_SPRITE_INDEX 0xff8cu
#define W_NPC_MOVEMENT_DIRECTIONS 0xcc5bu
#define W_NPC_NUM_SCRIPTED_STEPS 0xcf0fu
#define W_STATUS_FLAGS5 0xd730u
#define W_OVERRIDE_SIMULATED 0xcd3bu
#define W_SIMULATED_END 0xccd3u
#define W_JOY_IGNORE 0xcd6bu
#define W_UNUSED_OVERRIDE_INDEX 0xcd3au
#define SCRIPTED_NPC_MOVEMENT_BIT 0u
#define PORT_FLAG_N 0x40u
#define PORT_FLAG_H 0x20u
#define PORT_FLAG_Z 0x80u

void port_set_sprite_movement_bytes_to_ff(struct cpu_register_state *, port_u8 *);
void port_get_sprite_movement_byte1_pointer(struct memory_predicate_state *);

static void
xor_a(struct cpu_register_state *r)
{
	r->a = 0u;
	r->f = PORT_FLAG_Z;
}

static void
dec_a(struct cpu_register_state *r)
{
	port_u8 before = r->a;

	r->a = (port_u8)(before - 1u);
	r->f = PORT_FLAG_N;
	if (r->a == 0u)
		r->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0u)
		r->f |= PORT_FLAG_H;
}

/* Port of MoveSprite/MoveSprite_ in home/pathfinding.asm. */
__attribute__((noinline, used)) void
port_move_sprite(struct cpu_register_state *r, port_u8 *memory)
{
	port_u16 source = (port_u16)(((port_u16)r->d << 8) | r->e);
	port_u16 destination = W_NPC_MOVEMENT_DIRECTIONS;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_h;
	port_u8 saved_l;

	port_set_sprite_movement_bytes_to_ff(r, memory);
	saved_h = r->h;
	saved_l = r->l;
	saved_b = r->b;
	saved_c = r->c;
	{
		struct memory_predicate_state pointer = {0};

		pointer.registers = *r;
		pointer.value = memory[H_SPRITE_INDEX];
		port_get_sprite_movement_byte1_pointer(&pointer);
		*r = pointer.registers;
	}
	xor_a(r);
	memory[(port_u16)(((port_u16)r->h << 8) | r->l)] = r->a;

	r->h = (port_u8)(destination >> 8);
	r->l = (port_u8)destination;
	r->c = 0u;
	for (;;) {
		port_u8 value = memory[source++];

		r->a = value;
		memory[destination++] = value;
		r->c++;
		if (value == 0xffu)
			break;
	}
	r->d = (port_u8)(source >> 8);
	r->e = (port_u8)source;
	memory[W_NPC_NUM_SCRIPTED_STEPS] = r->c;
	r->b = saved_b;
	r->c = saved_c;
	r->h = (port_u8)(saved_h);
	r->l = (port_u8)(saved_l);
	memory[W_STATUS_FLAGS5] |= (port_u8)(1u << SCRIPTED_NPC_MOVEMENT_BIT);
	xor_a(r);
	memory[W_OVERRIDE_SIMULATED] = r->a;
	memory[W_SIMULATED_END] = r->a;
	dec_a(r);
	memory[W_JOY_IGNORE] = r->a;
	memory[W_UNUSED_OVERRIDE_INDEX] = r->a;
}
