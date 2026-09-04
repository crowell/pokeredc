#include "port_state.h"

#define W_BASE_COORD_X 0xd081
#define W_BASE_COORD_Y 0xd082
#define W_FB_TILE_COUNTER 0xd084
#define W_NUM_FB_TILES 0xd089
#define W_SUBANIM_TRANSFORM 0xd08b
#define W_ANIMATION_ID 0xd07c
#define W_SUBANIM_FRAME_DELAY 0xd086
#define W_FB_DEST_ADDR 0xd09c
#define W_FB_MODE 0xd09e
#define W_SHADOW_OAM 0xc300
#define OAM_XFLIP 0x20
#define OAM_YFLIP 0x40
#define FRAMEBLOCKMODE_02 0x02
#define FRAMEBLOCKMODE_03 0x03
#define FRAMEBLOCKMODE_04 0x04
#define GROWL 0x2d

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);
void port_animation_clean_oam(struct clear_sprites_state *state);

static port_u8
cp_equal_flags(void)
{
	return PORT_FLAG_Z | PORT_FLAG_N;
}

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if (left < right)
		flags |= PORT_FLAG_C;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	return flags;
}
static void
delay_frames(struct cpu_register_state *state, port_u8 frames)
{
	static const port_u8 no_vblank[256] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.registers.c = frames;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, no_vblank);
	*state = delay.registers;
}

static void
clean_oam(struct cpu_register_state *state, port_u8 *memory)
{
	struct clear_sprites_state clean;
	port_u16 offset;

	clean.registers = *state;
	for (offset = 0; offset < 160; offset++)
		clean.oam[offset] = memory[(port_u16)(W_SHADOW_OAM + offset)];
	port_animation_clean_oam(&clean);
	for (offset = 0; offset < 160; offset++)
		memory[(port_u16)(W_SHADOW_OAM + offset)] = clean.oam[offset];
}

/* Port of the complete DrawFrameBlock routine. */
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
			state->b = out_flags;
		} else if (transform == 2) {
			out_y = (port_u8)(base_y + y + 40);
			out_x = (port_u8)(168 - (port_u8)(base_x + x));
			out_flags = (port_u8)(flags ^ OAM_XFLIP);
			state->b = (port_u8)(base_x + x);
		} else if (transform == 3) {
			out_y = (port_u8)(136 - base_y + y);
			out_x = (port_u8)(168 - base_x + x);
			out_flags = flags;
			state->b = base_x;
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
		return;
	}

	delay_frames(state, memory[W_SUBANIM_FRAME_DELAY]);
	state->f = cp_flags(memory[W_FB_MODE], FRAMEBLOCKMODE_03);
	if (memory[W_FB_MODE] == FRAMEBLOCKMODE_03) {
		memory[W_FB_DEST_ADDR] = (port_u8)(destination >> 8);
		memory[W_FB_DEST_ADDR + 1] = (port_u8)destination;
		state->a = (port_u8)(destination >> 8);
		return;
	}
	state->f = cp_flags(memory[W_FB_MODE], FRAMEBLOCKMODE_04);
	if (memory[W_FB_MODE] == FRAMEBLOCKMODE_04) {
		state->a = memory[W_FB_MODE];
		return;
	}
	state->f = cp_flags(memory[W_ANIMATION_ID], GROWL);
	if (memory[W_ANIMATION_ID] != GROWL)
		clean_oam(state, memory);
	memory[W_FB_DEST_ADDR] = (port_u8)(W_SHADOW_OAM >> 8);
	memory[W_FB_DEST_ADDR + 1] = (port_u8)W_SHADOW_OAM;
	state->a = (port_u8)(W_SHADOW_OAM >> 8);
	state->h = (port_u8)(W_SHADOW_OAM >> 8);
	state->l = (port_u8)W_SHADOW_OAM;
}
