#include "port_state.h"

/* Port of AddPartyMon_WriteMovePP in engine/pokemon/add_mon.asm:
 *
 *   ld b, NUM_MOVES
 * .pploop:
 *   ld a, [hli] / and a / jr z, .empty
 *   dec a / push hl / push de / push bc
 *   ld hl, Moves / ld bc, MOVE_LENGTH / call AddNTimes   ; proven
 *   ld de, wMoveData / ld a, BANK(Moves) / call FarCopyData ; proven
 *   pop bc / pop de / pop hl
 *   ld a, [wMoveData + MOVE_PP]
 * .empty:
 *   inc de / ld [de], a / dec b / jr nz, .pploop
 *   ret
 *
 * The direct AddPartyMon caller and both callers through LoadMovePPs pass HL
 * at four move IDs and DE one byte below the four PP destinations. Empty
 * slots store zero. Filled slots execute the real AddNTimes and FarCopyData
 * ports, then store wMoveData[MOVE_PP]. */

void port_add_n_times(struct cpu_register_state *);
void port_far_copy_data(struct far_copy_data_state *, port_u8 *);

#define MOVES_TABLE_HL 0x4000u
#define MOVE_LENGTH 0x06u
#define BANK_MOVES 0x0eu
#define W_MOVE_DATA 0xcd6du
#define W_MOVE_DATA_PP (W_MOVE_DATA + 5u)
#define NUM_MOVES 4u

__attribute__((noinline, used)) void
port_add_party_mon_write_move_pp(
	struct add_party_mon_write_move_pp_state *state,
	port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	port_u16 hl;
	port_u16 de;
	port_u8 b;
	port_u8 c = registers->c;

	b = NUM_MOVES;
	hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	de = (port_u16)(((port_u16)registers->d << 8) | registers->e);

	for (;;) {
		port_u8 move = memory[hl];
		port_u8 old_b = b;
		port_u8 carry;

		hl++;
		registers->b = old_b;
		registers->c = c;
		registers->d = (port_u8)(de >> 8);
		registers->e = (port_u8)(de & 0xff);
		registers->h = (port_u8)(hl >> 8);
		registers->l = (port_u8)(hl & 0xff);
		registers->a = move;
		/* and a */
		registers->f = (port_u8)(PORT_FLAG_H |
		    ((move == 0) ? PORT_FLAG_Z : 0));
		if (move != 0) {
			registers->a = (port_u8)(move - 1u);
			registers->f = (port_u8)(PORT_FLAG_N |
			    ((registers->a == 0) ? PORT_FLAG_Z : 0) |
			    (((move & 0x0f) == 0) ? PORT_FLAG_H : 0));
			registers->h = (port_u8)(MOVES_TABLE_HL >> 8);
			registers->l = (port_u8)(MOVES_TABLE_HL & 0xff);
			registers->b = (port_u8)(MOVE_LENGTH >> 8);
			registers->c = (port_u8)(MOVE_LENGTH & 0xff);
			port_add_n_times(registers);
			registers->d = (port_u8)(W_MOVE_DATA >> 8);
			registers->e = (port_u8)(W_MOVE_DATA & 0xff);
			registers->a = BANK_MOVES;
			{
				struct far_copy_data_state fc;

				fc.registers = *registers;
				fc.requested_bank = state->requested_bank;
				fc.loaded_bank = state->loaded_bank;
				fc.rom_bank = state->rom_bank;
				port_far_copy_data(&fc, memory);
				*registers = fc.registers;
				state->requested_bank = fc.requested_bank;
				state->loaded_bank = fc.loaded_bank;
				state->rom_bank = fc.rom_bank;
			}
			registers->b = old_b;
			registers->c = c;
			registers->d = (port_u8)(de >> 8);
			registers->e = (port_u8)(de & 0xff);
			registers->h = (port_u8)(hl >> 8);
			registers->l = (port_u8)(hl & 0xff);
			registers->a = memory[W_MOVE_DATA_PP];
		}
		de++;
		memory[de] = registers->a;
		carry = registers->f & PORT_FLAG_C;
		b = (port_u8)(old_b - 1u);
		registers->f = (port_u8)(PORT_FLAG_N | carry |
		    ((b == 0) ? PORT_FLAG_Z : 0) |
		    (((old_b & 0x0f) == 0) ? PORT_FLAG_H : 0));
		registers->b = b;
		registers->d = (port_u8)(de >> 8);
		registers->e = (port_u8)(de & 0xff);
		if (b == 0)
			break;
	}

	registers->c = c;
}
