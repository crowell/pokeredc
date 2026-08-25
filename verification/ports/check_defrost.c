#include "port_state.h"

#define CD_H_WHOSE_TURN 0xfff3u
#define CD_W_PLAYER_MOVE_TYPE 0xcfd5u
#define CD_W_ENEMY_MOVE_TYPE 0xcfcfu
#define CD_W_ENEMY_MON_STATUS 0xcfe9u
#define CD_W_BATTLE_MON_STATUS 0xd018u
#define CD_W_ENEMY_MON_PARTY_POS 0xcfe8u
#define CD_W_PLAYER_MON_NUMBER 0xcc2fu
#define CD_W_ENEMY_MON_1_STATUS 0xd8a8u
#define CD_W_PARTY_MON_1_STATUS 0xd16fu
#define CD_PARTY_MON_STRUCT_LENGTH 0x2cu
#define CD_FIRE 0x14u
#define CD_FROZEN_MASK 0x20u
#define CD_FIRE_DEFROSTED_TEXT 0x7423u

void port_add_n_times(struct cpu_register_state *state);
void port_print_text(struct cpu_register_state *state, port_u8 *memory);

static void
check_defrost_and_flags(struct cpu_register_state *registers, port_u8 mask)
{
	registers->a &= mask;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
check_defrost_sub_fire(struct cpu_register_state *registers, port_u8 type)
{
	registers->a = (port_u8)(type - CD_FIRE);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((type & 0x0f) < (CD_FIRE & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (type < CD_FIRE)
		registers->f |= PORT_FLAG_C;
}

/* Port of the complete CheckDefrost function in engine/battle/effects.asm. */
__attribute__((noinline, used)) void
port_check_defrost(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 status_address;

	check_defrost_and_flags(registers, CD_FROZEN_MASK);
	if (registers->a == 0)
		return;

	registers->a = memory[CD_H_WHOSE_TURN];
	check_defrost_and_flags(registers, 0xff);
	if (registers->a == 0) {
		check_defrost_sub_fire(registers, memory[CD_W_PLAYER_MOVE_TYPE]);
		if (registers->a != 0)
			return;
		memory[CD_W_ENEMY_MON_STATUS] = registers->a;
		registers->h = (port_u8)(CD_W_ENEMY_MON_1_STATUS >> 8);
		registers->l = (port_u8)CD_W_ENEMY_MON_1_STATUS;
		registers->a = memory[CD_W_ENEMY_MON_PARTY_POS];
	} else {
		check_defrost_sub_fire(registers, memory[CD_W_ENEMY_MOVE_TYPE]);
		if (registers->a != 0)
			return;
		memory[CD_W_BATTLE_MON_STATUS] = registers->a;
		registers->h = (port_u8)(CD_W_PARTY_MON_1_STATUS >> 8);
		registers->l = (port_u8)CD_W_PARTY_MON_1_STATUS;
		registers->a = memory[CD_W_PLAYER_MON_NUMBER];
	}
	registers->b = 0;
	registers->c = CD_PARTY_MON_STRUCT_LENGTH;
	port_add_n_times(registers);
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	status_address = (port_u16)(((port_u16)registers->h << 8) |
	    registers->l);
	memory[status_address] = registers->a;
	registers->h = (port_u8)(CD_FIRE_DEFROSTED_TEXT >> 8);
	registers->l = (port_u8)CD_FIRE_DEFROSTED_TEXT;
	port_print_text(registers, memory);
}
