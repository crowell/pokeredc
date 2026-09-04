#include "port_state.h"

#define W_PLAYER_Y_PIXELS 0xc104u
#define W_PLAYER_X_PIXELS 0xc106u
#define W_PLAYER_FACING 0xc109u
#define W_WHICH_OFFSETS 0xcd50u
#define W_SHADOW_OAM 0xc300u
#define OAM_BLOCK 0x7060u

void port_get_cut_or_boulder_dust_animation_offsets(
	struct dust_animation_offsets_state *);
void port_write_oam_block(struct write_oam_block_state *);

/* Port of WriteCutOrBoulderDustAnimationOAMBlock in engine/overworld/cut.asm. */
__attribute__((noinline, used)) void
port_write_cut_or_boulder_dust_animation_oam_block(
	struct cpu_register_state *r, port_u8 *memory)
{
	struct dust_animation_offsets_state offsets = {0};
	struct write_oam_block_state block = {0};
	static const port_u8 source[8] = {
		0xfcu, 0x10u, 0xfdu, 0x10u, 0xfeu, 0x10u, 0xffu, 0x10u,
	};
	port_u8 i;
	port_u16 table;

	offsets.registers = *r;
	offsets.y_pixels = memory[W_PLAYER_Y_PIXELS];
	offsets.x_pixels = memory[W_PLAYER_X_PIXELS];
	offsets.direction = memory[W_PLAYER_FACING];
	offsets.which_offsets = memory[W_WHICH_OFFSETS];
	table = (port_u16)((memory[W_WHICH_OFFSETS] == 0 ? 0x708fu : 0x7097u) +
		((port_u16)(memory[W_PLAYER_FACING] >> 1)));
	offsets.fetched_x_offset = memory[table];
	offsets.fetched_y_offset = memory[table + 1u];
	port_get_cut_or_boulder_dust_animation_offsets(&offsets);
	*r = offsets.registers;

	block.registers = *r;
	block.registers.a = 9u;
	block.registers.d = (port_u8)(OAM_BLOCK >> 8);
	block.registers.e = (port_u8)OAM_BLOCK;
	block.registers.b = offsets.registers.b;
	block.registers.c = offsets.registers.c;
	for (i = 0; i < 8u; ++i)
		block.source[i] = source[i];
	for (i = 0; i < 16u; ++i)
		block.oam[i] = memory[W_SHADOW_OAM + 0x90u + i];
	port_write_oam_block(&block);
	*r = block.registers;
	for (i = 0; i < 16u; ++i)
		memory[W_SHADOW_OAM + 0x90u + i] = block.oam[i];
}
