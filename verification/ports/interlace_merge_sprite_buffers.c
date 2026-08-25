#include "port_state.h"

#define R_RAMB 0x4000u
#define S_SPRITE_BUFFER0 0xa000u
#define S_SPRITE_BUFFER1 0xa188u
#define S_SPRITE_BUFFER2 0xa310u
#define SPRITE_BUFFER_SIZE 392u
#define W_SPRITE_FLIPPED 0xd0aau
#define H_SPRITE_INTERLACE_COUNTER 0xff8bu
#define H_LOADED_ROM_BANK 0xffb8u
#define PIC_SIZE 49u

void port_copy_video_data(struct cpu_register_state *, port_u8 *);

static port_u16
interlace_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
interlace_set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
interlace_dec_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;

	registers->a--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
interlace_or_c(struct cpu_register_state *registers)
{
	registers->a |= registers->c;
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

/* Port of InterlaceMergeSpriteBuffers in home/pics.asm. */
__attribute__((noinline, used)) void
port_interlace_merge_sprite_buffers(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 output = interlace_pair(registers->d, registers->e);
	port_u16 hl = S_SPRITE_BUFFER2 + SPRITE_BUFFER_SIZE - 1;
	port_u16 de = S_SPRITE_BUFFER1 + SPRITE_BUFFER_SIZE - 1;
	port_u16 bc = S_SPRITE_BUFFER0 + SPRITE_BUFFER_SIZE - 1;

	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[R_RAMB] = registers->a;
	interlace_set_pair(&registers->h, &registers->l, hl);
	interlace_set_pair(&registers->d, &registers->e, de);
	interlace_set_pair(&registers->b, &registers->c, bc);
	registers->a = SPRITE_BUFFER_SIZE / 2;
	memory[H_SPRITE_INTERLACE_COUNTER] = registers->a;
	do {
		registers->a = memory[de--];
		memory[hl--] = registers->a;
		registers->a = memory[bc--];
		memory[hl--] = registers->a;
		registers->a = memory[de--];
		memory[hl--] = registers->a;
		registers->a = memory[bc--];
		memory[hl--] = registers->a;
		interlace_set_pair(&registers->h, &registers->l, hl);
		interlace_set_pair(&registers->d, &registers->e, de);
		interlace_set_pair(&registers->b, &registers->c, bc);
		registers->a = memory[H_SPRITE_INTERLACE_COUNTER];
		interlace_dec_a(registers);
		memory[H_SPRITE_INTERLACE_COUNTER] = registers->a;
	} while (registers->a != 0);

	registers->a = memory[W_SPRITE_FLIPPED];
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if (registers->a != 0) {
		bc = 2 * SPRITE_BUFFER_SIZE;
		hl = S_SPRITE_BUFFER1;
		interlace_set_pair(&registers->b, &registers->c, bc);
		interlace_set_pair(&registers->h, &registers->l, hl);
		do {
			port_u8 value = memory[hl];

			value = (port_u8)((value << 4) | (value >> 4));
			memory[hl++] = value;
			registers->f = value == 0 ? PORT_FLAG_Z : 0;
			bc--;
			interlace_set_pair(&registers->b, &registers->c, bc);
			interlace_set_pair(&registers->h, &registers->l, hl);
			registers->a = registers->b;
			interlace_or_c(registers);
		} while (registers->a != 0);
	}

	interlace_set_pair(&registers->h, &registers->l, output);
	interlace_set_pair(&registers->d, &registers->e,
		S_SPRITE_BUFFER1);
	registers->c = PIC_SIZE;
	registers->a = memory[H_LOADED_ROM_BANK];
	registers->b = registers->a;
	port_copy_video_data(registers, memory);
}
