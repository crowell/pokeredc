#include "port_state.h"

#define W_SHADOW_OAM 0xc300
#define W_BASE_COORD_X 0xd081
#define W_BASE_COORD_Y 0xd082
#define W_DROPLET_TILE 0xd09f
#define OAM_SIZE 160

void port_animation_clean_oam(struct clear_sprites_state *state);
void port_delay_frame(struct delay_frame_state *state,
	const port_u8 *observations);

static void
water_droplets_delay(struct cpu_register_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frame(&delay, acknowledged_vblank);
	*state = delay.registers;
}

static port_u8
water_cp(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;
	port_u8 result = (port_u8)(left - right);

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of _AnimationWaterDroplets in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_water_droplets(struct cpu_register_state *state, port_u8 *memory)
{
	struct clear_sprites_state clean;
	port_u16 hl = W_SHADOW_OAM;
	port_u16 offset;
	port_u8 x = memory[W_BASE_COORD_X];
	port_u8 y = memory[W_BASE_COORD_Y];
	port_u8 tile = memory[W_DROPLET_TILE];
	port_u8 flags;

	for (;;) {
		memory[hl++] = y;
		x = (port_u8)(x + 27);
		memory[hl++] = x;
		memory[hl++] = tile;
		memory[hl++] = 0;
		flags = water_cp(x, 144);
		if (x < 144)
			continue;
		x = (port_u8)(x - 168);
		memory[W_BASE_COORD_X] = x;
		y = (port_u8)(y + 16);
		memory[W_BASE_COORD_Y] = y;
		flags = water_cp(y, 112);
		if (y < 112)
			continue;
		break;
	}

	state->a = y;
	state->f = flags;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;

	clean.registers = *state;
	for (offset = 0; offset < OAM_SIZE; offset++)
		clean.oam[offset] = memory[(port_u16)(W_SHADOW_OAM + offset)];
	port_animation_clean_oam(&clean);
	for (offset = 0; offset < OAM_SIZE; offset++)
		memory[(port_u16)(W_SHADOW_OAM + offset)] = clean.oam[offset];
	*state = clean.registers;
	water_droplets_delay(state);
}
