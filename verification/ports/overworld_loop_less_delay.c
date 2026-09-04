#include "port_state.h"

#define W_MAP_PAL_OFFSET 0xd35du
#define FADE_PAL4 0x2116u
#define R_BGP 0xff47u
#define R_OBP0 0xff48u
#define R_OBP1 0xff49u

void port_delay_frame(struct delay_frame_state *, const port_u8 *);
void port_load_gb_pal(struct load_gb_pal_state *);

/* Port of OverworldLoopLessDelay through the LoadGBPal call boundary. */
__attribute__((noinline, used)) void
port_overworld_loop_less_delay(struct cpu_register_state *state, port_u8 *memory)
{
	struct delay_frame_state delay = {0};
	const port_u8 observations[] = {0};
	struct load_gb_pal_state palette = {0};

	delay.registers = *state;
	port_delay_frame(&delay, observations);
	palette.registers = delay.registers;
	palette.map_pal_offset = memory[W_MAP_PAL_OFFSET];
	palette.fetched[0] = memory[FADE_PAL4];
	palette.fetched[1] = memory[FADE_PAL4 + 1];
	palette.fetched[2] = memory[FADE_PAL4 + 2];
	port_load_gb_pal(&palette);
	memory[R_BGP] = palette.background_palette;
	memory[R_OBP0] = palette.object_palette0;
	memory[R_OBP1] = palette.object_palette1;
	*state = palette.registers;
}
