#include "port_state.h"

#define S_GAME_DATA 0xa598u
#define S_GAME_DATA_END 0xb523u
#define S_MAIN_DATA_CHECKSUM 0xb523u
#define S_PARTY_DATA 0xaf2cu
#define W_PARTY_DATA_START 0xd163u
#define W_PARTY_DATA_END 0xd2f7u
#define S_MAIN_DATA 0xa5a3u
#define W_POKEDEX_OWNED 0xd2f7u
#define W_POKEDEX_SEEN_END 0xd31du
#define R_RAMG 0x0000u
#define R_RAMB 0x4000u
#define R_BMODE 0x6000u
#define RAMG_SRAM_ENABLE 0x0au
#define RAMG_SRAM_DISABLE 0x00u
#define BMODE_ADVANCED 0x01u
#define BMODE_SIMPLE 0x00u

void port_calc_checksum(struct checksum_loop_state *, const port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);

static port_u8
load_checksum(struct cpu_register_state *registers, const port_u8 *memory)
{
	struct checksum_loop_state checksum;
	checksum.registers = *registers;
	checksum.registers.h = (port_u8)(S_GAME_DATA >> 8);
	checksum.registers.l = (port_u8)S_GAME_DATA;
	checksum.registers.b = (port_u8)((S_GAME_DATA_END - S_GAME_DATA) >> 8);
	checksum.registers.c = (port_u8)(S_GAME_DATA_END - S_GAME_DATA);
	port_calc_checksum(&checksum, memory + S_GAME_DATA);
	*registers = checksum.registers;
	/* The assembly caller performs `ld c, a` immediately after returning. */
	registers->c = checksum.registers.a;
	return checksum.registers.a;
}

static void
load_copy(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 source, port_u16 destination, port_u16 length)
{
	registers->h = (port_u8)(source >> 8);
	registers->l = (port_u8)source;
	registers->d = (port_u8)(destination >> 8);
	registers->e = (port_u8)destination;
	registers->b = (port_u8)(length >> 8);
	registers->c = (port_u8)length;
	port_copy_data(registers, memory);
}

/* Port of LoadPartyAndDexData in engine/menus/save.asm. */
__attribute__((noinline, used)) void
port_load_party_and_dex_data(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u8 checksum;
	port_u8 final_a;

	memory[R_RAMG] = RAMG_SRAM_ENABLE;
	memory[R_BMODE] = BMODE_ADVANCED;
	memory[R_RAMB] = BMODE_ADVANCED;
	checksum = load_checksum(registers, memory);
	if (memory[S_MAIN_DATA_CHECKSUM] != checksum) {
		registers->a = 0;
		registers->f = PORT_FLAG_C;
		memory[R_BMODE] = BMODE_SIMPLE;
		memory[R_RAMG] = RAMG_SRAM_DISABLE;
		return;
	}

	load_copy(registers, memory, S_PARTY_DATA, W_PARTY_DATA_START,
		W_PARTY_DATA_END - W_PARTY_DATA_START);
	load_copy(registers, memory, S_MAIN_DATA, W_POKEDEX_OWNED,
		W_POKEDEX_SEEN_END - W_POKEDEX_OWNED);
	final_a = registers->a;
	registers->a = 0;
	registers->f = (port_u8)(PORT_FLAG_H |
		(final_a == 0 ? PORT_FLAG_Z : 0));
	memory[R_BMODE] = BMODE_SIMPLE;
	memory[R_RAMG] = RAMG_SRAM_DISABLE;
}
