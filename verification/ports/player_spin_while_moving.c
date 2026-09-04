#include "port_state.h"

#define W_PLAYER_SPIN_DELTA_Y 0xcd3du
#define W_PLAYER_SPIN_MAX_Y 0xcd3eu
#define W_PLAYER_SPIN_FRAME_DELAY 0xcd3fu
#define W_SPRITE_PLAYER_Y_PIXELS 0xc104u

void port_spin_player_sprite(struct cpu_register_state *, port_u8 *);
void port_delay_frames(struct delay_frame_state *, const port_u8 *);

static void
add_a_c(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->c;
	port_u16 wide = (port_u16)left + right;

	registers->a = (port_u8)wide;
	registers->f = (registers->a == 0 ? PORT_FLAG_Z : 0)
		| ((left & 0x0fu) + (right & 0x0fu) > 0x0fu ? PORT_FLAG_H : 0)
		| (wide > 0xffu ? PORT_FLAG_C : 0);
}

static void
compare_a_c(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->c;

	registers->f = PORT_FLAG_N | (left == right ? PORT_FLAG_Z : 0)
		| ((left & 0x0fu) < (right & 0x0fu) ? PORT_FLAG_H : 0)
		| (left < right ? PORT_FLAG_C : 0);
}

/* Port of PlayerSpinWhileMovingUpOrDown in player_animations.asm. */
__attribute__((noinline, used)) void
port_player_spin_while_moving_up_or_down(struct cpu_register_state *registers,
	port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };

	for (;;) {
		struct delay_frame_state delay;

		port_spin_player_sprite(registers, memory);
		registers->a = memory[W_PLAYER_SPIN_DELTA_Y];
		registers->c = registers->a;
		registers->a = memory[W_SPRITE_PLAYER_Y_PIXELS];
		add_a_c(registers);
		memory[W_SPRITE_PLAYER_Y_PIXELS] = registers->a;
		registers->c = registers->a;
		registers->a = memory[W_PLAYER_SPIN_MAX_Y];
		compare_a_c(registers);
		if (registers->f & PORT_FLAG_Z)
			return;
		registers->a = memory[W_PLAYER_SPIN_FRAME_DELAY];
		registers->c = registers->a;
		delay.registers = *registers;
		delay.vblank_occurred = 0;
		delay.observed_vblank = 0;
		port_delay_frames(&delay, acknowledged_vblank);
		*registers = delay.registers;
	}
}
