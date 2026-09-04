#include "port_state.h"

#define W_NAMING_SCREEN_LETTER 0xceedu
#define W_STRING_BUFFER 0xcf4bu

void port_calc_string_length(struct cpu_register_state *, port_u8 *);
port_u8 port_is_in_array(struct computed_load_state *, const port_u8 *);

/* Port of DakutensAndHandakutens in engine/menus/naming_screen.asm. */
__attribute__((noinline, used)) void
port_dakutens_and_handakutens(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 saved_de;
	struct computed_load_state search;
	port_u8 found;
	port_u16 hl;

	/* push de: the dakuten table pointer leaves the stack in HL below,
	 * so native carries the entry DE explicitly across CalcStringLength. */
	saved_de = (port_u16)(((port_u16)registers->d << 8) | registers->e);

	/* call CalcStringLength: HL runs wStringBuffer up to the '@'. */
	port_calc_string_length(registers, memory);

	/* dec hl; ld a, [hl]: fetch the last character of the name. */
	hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	hl--;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->a = memory[hl];

	/* pop hl restores the table pointer; ld de, $2 is the pair stride. */
	search.registers = *registers;
	search.registers.h = (port_u8)(saved_de >> 8);
	search.registers.l = (port_u8)saved_de;
	search.registers.d = 0;
	search.registers.e = 2;

	/* call IsInArray; ret nc leaves the not-found registers untouched. */
	found = port_is_in_array(&search, memory);
	*registers = search.registers;
	if (found != 1u)
		return;

	/* inc hl; ld a, [hl]; ld [wNamingScreenLetter], a. */
	hl = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	hl++;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	registers->a = memory[hl];
	memory[W_NAMING_SCREEN_LETTER] = registers->a;
}
