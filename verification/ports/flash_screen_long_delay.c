#include "port_state.h"

#define W_FLASH_SCREEN_LONG_COUNTER 0xd08a

/* Port of FlashScreenLongDelay when the long-screen counter is 3. */
__attribute__((noinline, used)) void
port_flash_screen_long_delay_counter3(struct cpu_register_state *state, port_u8 *memory)
{
	memory[W_FLASH_SCREEN_LONG_COUNTER] = 3;
	state->a = 3;
	state->c = 2;
	state->f = 0;
}
