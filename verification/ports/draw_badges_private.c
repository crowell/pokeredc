#include "port_state.h"

struct draw_badges_private_state {
	struct cpu_register_state registers;
	port_u8 badge_or_face_tiles[8];
};

/* Port of DrawBadges through CopyData entry. */
__attribute__((noinline, used)) void
port_draw_badges_private(struct draw_badges_private_state *state)
{
	state->registers.d = 0xcd;
	state->registers.e = 0x3f;
	state->registers.h = 0x6a;
	state->registers.l = 0x96;
	state->registers.b = 0;
	state->registers.c = 8;
	state->badge_or_face_tiles[0] = 0x20;
	state->badge_or_face_tiles[1] = 0x28;
	state->badge_or_face_tiles[2] = 0x30;
	state->badge_or_face_tiles[3] = 0x38;
	state->badge_or_face_tiles[4] = 0x40;
	state->badge_or_face_tiles[5] = 0x48;
	state->badge_or_face_tiles[6] = 0x50;
	state->badge_or_face_tiles[7] = 0x58;
}
