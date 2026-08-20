#include "port_state.h"

#define W_BASE_COORD_X 0xd081
#define W_BASE_COORD_Y 0xd082
#define W_FB_TILE_COUNTER 0xd084
#define W_NUM_FB_TILES 0xd089
#define W_SUBANIM_TRANSFORM 0xd08b
#define W_FB_DEST_ADDR 0xd09c
#define W_FB_MODE 0xd09e
#define OAM_XFLIP 0x20
#define OAM_YFLIP 0x40
#define FRAMEBLOCKMODE_02 0x02

static port_u8
cp_equal_flags(void)
{
	return PORT_FLAG_Z;
}

/* Port of the no-transformation, mode-02 DrawFrameBlock path. */
__attribute__((noinline, used)) void
port_draw_frame_block(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 frame = (port_u16)(((port_u16)state->b << 8) | state->c);
	port_u16 destination;
	port_u8 count;
	port_u8 index;
	port_u8 transform;
	port_u8 base_x;
	port_u8 base_y;

	count = memory[frame];
	memory[W_NUM_FB_TILES] = count;
	destination = (port_u16)(((port_u16)memory[W_FB_DEST_ADDR] << 8) |
		memory[W_FB_DEST_ADDR + 1]);
	memory[W_FB_TILE_COUNTER] = 0;
	transform = memory[W_SUBANIM_TRANSFORM];
	base_x = memory[W_BASE_COORD_X];
	base_y = memory[W_BASE_COORD_Y];

	for (index = 0; index < count; index++) {
		port_u16 entry = (port_u16)(frame + 1 + (port_u16)index * 4);
		port_u8 y = memory[entry];
		port_u8 x = memory[(port_u16)(entry + 1)];
		port_u8 tile = memory[(port_u16)(entry + 2)];
		port_u8 flags = memory[(port_u16)(entry + 3)];
		port_u8 out_y;
		port_u8 out_x;
		port_u8 out_flags;

		memory[W_FB_TILE_COUNTER] = (port_u8)(index + 1);
		if (transform == 1) {
			out_y = (port_u8)(136 - (port_u8)(base_y + y));
			out_x = (port_u8)(168 - (port_u8)(base_x + x));
			if (flags == 0)
				out_flags = OAM_YFLIP | OAM_XFLIP;
			else if (flags == OAM_XFLIP)
				out_flags = OAM_YFLIP;
			else if (flags == OAM_YFLIP)
				out_flags = OAM_XFLIP;
			else
				out_flags = 0;
		} else if (transform == 2) {
			out_y = (port_u8)(base_y + y + 40);
			out_x = (port_u8)(168 - (port_u8)(base_x + x));
			out_flags = (port_u8)(flags ^ OAM_XFLIP);
		} else if (transform == 3) {
			out_y = (port_u8)(136 - base_y + y);
			out_x = (port_u8)(168 - base_x + x);
			out_flags = flags;
		} else {
			out_y = (port_u8)(base_y + y);
			out_x = (port_u8)(base_x + x);
			out_flags = flags;
		}

		memory[destination] = out_y;
		memory[(port_u16)(destination + 1)] = out_x;
		memory[(port_u16)(destination + 2)] = (port_u8)(tile + 0x31);
		memory[(port_u16)(destination + 3)] = out_flags;
		destination = (port_u16)(destination + 4);
	}

	state->a = (port_u8)(destination >> 8);
	state->c = memory[W_FB_TILE_COUNTER];
	state->d = (port_u8)(destination >> 8);
	state->e = (port_u8)destination;
	state->h = (port_u8)((frame + 1 + (port_u16)count * 4) >> 8);
	state->l = (port_u8)(frame + 1 + (port_u16)count * 4);
	state->f = cp_equal_flags();

	if (memory[W_FB_MODE] == FRAMEBLOCKMODE_02) {
		memory[W_FB_DEST_ADDR] = (port_u8)(destination >> 8);
		memory[W_FB_DEST_ADDR + 1] = (port_u8)destination;
	}
}
