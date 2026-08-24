#include "port_state.h"

/* Port of PrintLevelCommon in home/pokemon.asm:
 *
 *   ld [wTempByteValue], a    ; $d1ed
 *   ld de, wTempByteValue     ; DE = $d1ed
 *   ld b, LEFT_ALIGN | 1      ; B = $41
 *   jp PrintNumber
 *
 * Composition: stores A to wTempByteValue, sets up DE and B, then tails into
 * the proven port_print_number through an explicit print_number_state bridge.
 * The print_number_state's non-register fields are zero-initialized (they are
 * internal scratch state that PrintNumber initializes itself).
 */

void port_print_number(struct print_number_state *);

#define W_TEMP_BYTE_VALUE 0xd11eu

__attribute__((noinline, used)) void
port_print_level_common(struct cpu_register_state *state, port_u8 *memory)
{
	struct print_number_state pn;
	port_u8 i;

	/* ld [wTempByteValue], a */
	memory[W_TEMP_BYTE_VALUE] = state->a;

	/* ld de, wTempByteValue */
	state->d = (port_u8)(W_TEMP_BYTE_VALUE >> 8);
	state->e = (port_u8)(W_TEMP_BYTE_VALUE & 0xff);

	/* ld b, LEFT_ALIGN | 1 ($41) */
	state->b = 0x41u;

	/* jp PrintNumber — bridge through print_number_state */
	pn.registers = *state;
	for (i = 0; i < sizeof(pn.number) / sizeof(pn.number[0]); i++)
		pn.number[i] = memory[W_TEMP_BYTE_VALUE + i];
	pn.past_leading_zeroes = 0;
	pn.power[0] = memory[W_TEMP_BYTE_VALUE + 3];
	pn.power[1] = memory[W_TEMP_BYTE_VALUE + 4];
	pn.power[2] = memory[W_TEMP_BYTE_VALUE + 5];
	pn.saved_number[0] = memory[0xff95];
	pn.saved_number[1] = memory[0xff96];
	pn.saved_number[2] = memory[0xff97];
	pn.source[0] = memory[0xd1ed];
	pn.source[1] = memory[0xd1ee];
	pn.source[2] = memory[0xd1ef];
	pn.written = 0;
	pn.did_write = 0;
	pn.write_h = 0;
	pn.write_l = 0;
	pn.saved_b = state->b;
	pn.saved_c = state->c;
	pn.saved_d = state->d;
	pn.saved_e = state->e;

	port_print_number(&pn);

	*state = pn.registers;
	memory[W_TEMP_BYTE_VALUE] = pn.number[0];
}
