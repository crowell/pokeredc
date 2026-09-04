#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_Y_COORD 0xd361u
#define W_X_COORD 0xd362u
#define W_SEAFOAM_B3F_SCRIPT 0xd666u
#define W_SEAFOAM_B4F_SCRIPT 0xd668u
#define W_WALK_BIKE_SURF_STATE 0xd700u
#define W_WALK_BIKE_SURF_STATE_COPY 0xd11au
#define W_STATUS_FLAGS6 0xd732u
#define FORCED_BIKE_SURF_MAPS 0x43e6u

static void cp_flags(struct cpu_register_state *registers, port_u8 left,
    port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;
	if (result == 0u) flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu)) flags |= PORT_FLAG_H;
	if (left < right) flags |= PORT_FLAG_C;
	registers->f = flags;
}

static void set_hl(struct cpu_register_state *registers, port_u16 value)
{
	registers->h = (port_u8)(value >> 8);
	registers->l = (port_u8)value;
}

void port_force_bike_or_surf(struct force_bike_or_surf_state *, port_u8 *);

/* Port of CheckForceBikeOrSurf in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_check_force_bike_or_surf(struct force_bike_or_surf_state *state,
    port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u8 status = memory[W_STATUS_FLAGS6];
	port_u8 current_map;
	port_u8 y;
	port_u8 x;
	port_u16 pointer;

	set_hl(registers, W_STATUS_FLAGS6);
	/* BIT ALWAYS_ON_BIKE,(HL): H is set, C is preserved, and Z reports the
	 * tested bit.  The nonzero path returns directly. */
	registers->f = (port_u8)((registers->f & PORT_FLAG_C) | PORT_FLAG_H |
	    ((status & (1u << 5)) == 0u ? PORT_FLAG_Z : 0u));
	if ((status & (1u << 5)) != 0u)
		return;

	current_map = memory[W_CUR_MAP];
	y = memory[W_Y_COORD];
	x = memory[W_X_COORD];
	registers->b = y;
	registers->c = x;
	registers->d = current_map;
	pointer = FORCED_BIKE_SURF_MAPS;
	set_hl(registers, pointer);

	for (;;) {
		port_u8 map = memory[pointer++];
		set_hl(registers, pointer);
		registers->a = map;
		cp_flags(registers, map, 0xffu);
		if (map == 0xffu)
			return;
		cp_flags(registers, map, current_map);
		if (map != current_map) {
			pointer = (port_u16)(pointer + 2u);
			set_hl(registers, pointer);
			continue;
		}

		port_u8 entry_y = memory[pointer++];
		set_hl(registers, pointer);
		registers->a = entry_y;
		cp_flags(registers, entry_y, y);
		if (entry_y != y) {
			pointer = (port_u16)(pointer + 1u);
			set_hl(registers, pointer);
			continue;
		}

		port_u8 entry_x = memory[pointer++];
		set_hl(registers, pointer);
		registers->a = entry_x;
		cp_flags(registers, entry_x, x);
		if (entry_x != x)
			continue;

		cp_flags(registers, current_map, 0xa1u);
		registers->a = 2u;
		memory[W_SEAFOAM_B3F_SCRIPT] = registers->a;
		if (current_map == 0xa1u) {
			memory[W_WALK_BIKE_SURF_STATE] = 2u;
			memory[W_WALK_BIKE_SURF_STATE_COPY] = 2u;
			return;
		}

		cp_flags(registers, current_map, 0xa2u);
		registers->a = 2u;
		memory[W_SEAFOAM_B4F_SCRIPT] = registers->a;
		if (current_map == 0xa2u) {
			memory[W_WALK_BIKE_SURF_STATE] = 2u;
			memory[W_WALK_BIKE_SURF_STATE_COPY] = 2u;
			return;
		}

		memory[W_STATUS_FLAGS6] = (port_u8)(status | (1u << 5));
		set_hl(registers, W_STATUS_FLAGS6);
		registers->a = 1u;
		memory[W_WALK_BIKE_SURF_STATE] = 1u;
		memory[W_WALK_BIKE_SURF_STATE_COPY] = 1u;
		port_force_bike_or_surf(state, memory);
		return;
	}
}
