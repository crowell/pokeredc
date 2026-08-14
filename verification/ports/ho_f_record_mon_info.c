#include "port_state.h"

/* Port of HoFRecordMonInfo in engine/movie/hall_of_fame.asm.
 *
 * Writes one Hall-of-Fame record: the mon's species and level followed by its
 * name, into the table at wHallOfFame + HOF_MON * wHoFPartyMonIndex. The
 * original transfers to CopyData for the name copy; the port inlines it. */

#define HOF_W_HALL_OF_FAME 0xcc5bu
#define HOF_W_HOF_PARTY_MON_INDEX 0xcd3eu
#define HOF_W_HOF_MON_SPECIES 0xcd3du
#define HOF_W_HOF_MON_LEVEL 0xcd3fu
#define HOF_W_NAME_BUFFER 0xcd6du
#define HOF_HOF_MON 0x10u
#define HOF_NAME_LENGTH 11u

__attribute__((noinline, used)) void
port_ho_f_record_mon_info(
	struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	port_u8 index = memory[HOF_W_HOF_PARTY_MON_INDEX];
	port_u16 base = (port_u16)(HOF_W_HALL_OF_FAME + (port_u16)(HOF_HOF_MON * index));
	memory[base] = memory[HOF_W_HOF_MON_SPECIES];
	memory[base + 1u] = memory[HOF_W_HOF_MON_LEVEL];
	port_u16 dst = (port_u16)(base + 2u);
	port_u8 i;
	for (i = 0; i < HOF_NAME_LENGTH; i++) {
		memory[dst + i] = memory[HOF_W_NAME_BUFFER + i];
	}
}
