#include "port_state.h"

#define V_CHARS1_TILE_7F 0x8ff0u
#define LEDGE_HOPPING_SHADOW 0x6708u
#define LEDGE_HOPPING_SHADOW_OAM_BLOCK 0x6710u
#define W_SHADOW_OAM 0xc300u
#define SHADOW_OAM_BLOCK 0x90u
#define OAM_PAL1 0x10u
#define OAM_XFLIP 0x20u
#define OAM_YFLIP 0x40u

void port_copy_video_data_double(struct cpu_register_state *, port_u8 *);
void port_write_oam_block(struct write_oam_block_state *);

/* Port of LoadHoppingShadowOAM in engine/overworld/ledges.asm. */
__attribute__((noinline, used)) void
port_load_hopping_shadow_oam(struct cpu_register_state *registers,
	port_u8 *memory)
{
	struct write_oam_block_state block = {0};

	/* Copy the one 1bpp tile into the last character slot used by the
	 * hopping shadow.  CopyVideoDataDouble owns the complete VBlank/bank
	 * transition and is deliberately called as the production port. */
	registers->h = (port_u8)(V_CHARS1_TILE_7F >> 8);
	registers->l = (port_u8)V_CHARS1_TILE_7F;
	registers->d = (port_u8)(LEDGE_HOPPING_SHADOW >> 8);
	registers->e = (port_u8)LEDGE_HOPPING_SHADOW;
	registers->b = 6;
	registers->c = 1;
	port_copy_video_data_double(registers, memory);

	/* The four OAM entries are the literal LedgeHoppingShadowOAMBlock.
	 * WriteOAMBlock performs the same indexed OAM placement and register
	 * effects as the assembly callee; copy its complete OAM result into the
	 * canonical shadow-OAM memory region afterwards. */
	block.registers = *registers;
	block.registers.a = 9;
	block.registers.b = 0x54;
	block.registers.c = 0x48;
	block.registers.d = (port_u8)(LEDGE_HOPPING_SHADOW_OAM_BLOCK >> 8);
	block.registers.e = (port_u8)LEDGE_HOPPING_SHADOW_OAM_BLOCK;
	block.source[0] = 0xff;
	block.source[1] = OAM_PAL1;
	block.source[2] = 0xff;
	block.source[3] = OAM_PAL1 | OAM_XFLIP;
	block.source[4] = 0xff;
	block.source[5] = OAM_PAL1 | OAM_YFLIP;
	block.source[6] = 0xff;
	block.source[7] = OAM_PAL1 | OAM_XFLIP | OAM_YFLIP;
	port_write_oam_block(&block);
	for (port_u8 index = 0; index < sizeof(block.oam); ++index)
		memory[W_SHADOW_OAM + SHADOW_OAM_BLOCK + index] = block.oam[index];
	*registers = block.registers;
}
