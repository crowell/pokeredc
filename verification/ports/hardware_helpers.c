#include "port_state.h"

/* Port of GBPalNormal in home/palettes.asm. */
__attribute__((noinline, used)) void
port_gb_pal_normal(struct black_screen_state *state)
{
	state->registers.a = 0xe4;
	state->background_palette = state->registers.a;
	state->registers.a = 0xd0;
	state->object_palette0 = state->registers.a;
}

/* Port of GBPalWhiteOut in home/palettes.asm. */
__attribute__((noinline, used)) void
port_gb_pal_white_out(struct black_screen_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->background_palette = 0;
	state->object_palette0 = 0;
	state->object_palette1 = 0;
}

/* Port of EnableLCD in home/lcd.asm; background_palette represents rLCDC. */
__attribute__((noinline, used)) void
port_enable_lcd(struct black_screen_state *state)
{
	state->registers.a = state->background_palette | 0x80;
	state->background_palette = state->registers.a;
}

/* Port of Serial_TryEstablishingExternallyClockedConnection. */
__attribute__((noinline, used)) void
port_serial_try_establishing_externally_clocked_connection(
	struct black_screen_state *state)
{
	state->registers.a = 2;
	state->background_palette = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->object_palette0 = 0;
	state->registers.a = 0x80;
	state->object_palette1 = state->registers.a;
}
