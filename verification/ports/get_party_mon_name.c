#include "port_state.h"

/*
 * Port of GetPartyMonName in home/pokemon.asm (the shared tail reached by
 * GetPartyMonName2). Copies NAME_LENGTH bytes from the party-mon nickname
 * table into wNameBuffer. The original body is:
 *
 *   push hl
 *   push bc
 *   call SkipFixedLengthTextEntries ; hl += a * NAME_LENGTH
 *   ld de, wNameBuffer
 *   push de
 *   ld bc, NAME_LENGTH
 *   call CopyData                ; copy NAME_LENGTH bytes hl -> de
 *   pop de / pop bc / pop hl / ret
 *
 * A (party index) and HL (base of the nickname table, i.e. wPartyMonNicks)
 * arrive already loaded by the caller (GetPartyMonName2). The copy reuses the
 * proven SkipFixedLengthTextEntries and CopyData ports.
 */

#define W_PARTY_MON_NICKS 0xd2b5
#define W_NAME_BUFFER     0xcd6d
#define NAME_LENGTH       11

extern void port_skip_fixed_length_text_entries(struct cpu_register_state *state);
extern void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_get_party_mon_name(struct cpu_register_state *state, port_u8 *memory)
{
	/* HL holds the nickname-table base (wPartyMonNicks); A is the index. */
	port_skip_fixed_length_text_entries(state); /* hl += a * NAME_LENGTH */

	state->d = (port_u8)(W_NAME_BUFFER >> 8);
	state->e = (port_u8)W_NAME_BUFFER;
	state->b = 0;
	state->c = NAME_LENGTH;

	port_copy_data(state, memory); /* copy NAME_LENGTH bytes [hl] -> [de] */
}
