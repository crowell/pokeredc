#include "port_state.h"

#define W_PLAYER_FACING 0xc109u
#define W_SHADOW_OAM_SPRITE36 0xc390u
#define W_UPDATE_SPRITES_ENABLED 0xcfcbu
#define W_WHICH_ANIMATION_OFFSETS 0xcd50u
#define W_COORD_ADJUSTMENT_AMOUNT 0xd08au
#define R_OBP1 0xff49u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_load_smoke_tile_four_times(struct cpu_register_state *, port_u8 *);
void port_write_cut_or_boulder_dust_animation_oam_block(
	struct cpu_register_state *, port_u8 *);
void port_get_move_boulder_dust_function_pointer_memory(
	struct cpu_register_state *, port_u8 *, const port_u8 *);
void port_adjust_oam_block_x_pos(struct adjust_oam_block_state *);
void port_adjust_oam_block_y_pos(struct adjust_oam_block_state *);
void port_delay3(struct cpu_register_state *, port_u8 *);
void port_load_player_sprite_graphics(struct cpu_register_state *, port_u8 *);

static const port_u8 move_boulder_dust_table[16] = {
	0xff, 0x00, 0x50, 0x53,
	0x01, 0x00, 0x50, 0x53,
	0x01, 0x01, 0x37, 0x53,
	0xff, 0x01, 0x37, 0x53,
};

static void
adjust_boulder_oam(struct cpu_register_state *registers, port_u8 *memory)
{
	struct adjust_oam_block_state adjust;
	port_u16 de = (port_u16)(((port_u16)registers->d << 8) | registers->e);
	port_u16 base = (port_u16)(de - 1u);
	port_u8 i;

	adjust.registers = *registers;
	/* LD BC,.returnAddress / PUSH BC leaves B=$5f at the JP target. */
	adjust.registers.b = 0x5f;
	adjust.registers.c = 4;
	adjust.adjustment = memory[W_COORD_ADJUSTMENT_AMOUNT];
	for (i = 0; i < 16u; ++i)
		adjust.oam[i] = memory[(port_u16)(base + i)];

	if (memory[W_PLAYER_FACING] < 8u)
		port_adjust_oam_block_y_pos(&adjust);
	else
		port_adjust_oam_block_x_pos(&adjust);

	*registers = adjust.registers;
	for (i = 0; i < 16u; ++i)
		memory[(port_u16)(base + i)] = adjust.oam[i];
}

static void
write_boulder_dust_oam_farcall(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_flags = registers->f;

	/* farcall WriteCutOrBoulderDustAnimationOAMBlock: bank 3, $7055. */
	registers->b = 3;
	registers->h = 0x70;
	registers->l = 0x55;
	registers->a = registers->b;
	memory[H_LOADED_ROM_BANK] = registers->a;
	memory[R_ROMB] = registers->a;
	registers->b = 0x35;
	registers->c = 0xe4;
	port_write_cut_or_boulder_dust_animation_oam_block(registers, memory);

	/* Bankswitch.Return pops the saved AF into BC and restores its bank. */
	registers->b = saved_bank;
	registers->c = saved_flags;
	registers->a = registers->b;
	memory[H_LOADED_ROM_BANK] = registers->a;
	memory[R_ROMB] = registers->a;
}

static void
xor_a(struct cpu_register_state *registers, port_u8 value)
{
	registers->a ^= value;
	registers->f = registers->a == 0 ? PORT_FLAG_Z : 0;
}

static void
dec_c(struct cpu_register_state *registers)
{
	port_u8 before = registers->c;

	registers->c--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((before & 0x0fu) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Port of AnimateBoulderDust in engine/overworld/dust_smoke.asm. */
__attribute__((noinline, used)) void
port_animate_boulder_dust(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 saved_update;
	port_u8 saved_flags;
	port_u8 steps;

	registers->a = 1;
	memory[W_WHICH_ANIMATION_OFFSETS] = registers->a;
	registers->a = memory[W_UPDATE_SPRITES_ENABLED];
	saved_update = registers->a;
	saved_flags = registers->f;
	registers->a = 0xff;
	memory[W_UPDATE_SPRITES_ENABLED] = registers->a;
	registers->a = 0xe4;
	memory[R_OBP1] = registers->a;
	port_load_smoke_tile_four_times(registers, memory);
	write_boulder_dust_oam_farcall(registers, memory);

	steps = 8;
	do {
		port_u8 saved_loop_b = registers->b;

		port_get_move_boulder_dust_function_pointer_memory(registers,
			memory, move_boulder_dust_table);
		adjust_boulder_oam(registers, memory);
		registers->a = memory[R_OBP1];
		xor_a(registers, 0x64);
		memory[R_OBP1] = registers->a;
		port_delay3(registers, memory);
		registers->b = saved_loop_b;
		registers->c = steps;
		dec_c(registers);
		steps = registers->c;
	} while (steps != 0);

	registers->a = saved_update;
	registers->f = saved_flags;
	memory[W_UPDATE_SPRITES_ENABLED] = registers->a;
	port_load_player_sprite_graphics(registers, memory);
}
