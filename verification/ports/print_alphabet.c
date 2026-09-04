#include "port_state.h"

#define W_TILE_MAP 0xc3a0u
#define W_ALPHABET_CASE 0xceebu
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define LOWER_CASE_ALPHABET 0x679eu
#define UPPER_CASE_ALPHABET 0x67d6u
#define SCREEN_WIDTH 20u

void port_place_string(struct cpu_register_state *, port_u8 *);
void port_delay3(struct cpu_register_state *, port_u8 *);

/* Port of PrintAlphabet in engine/menus/naming_screen.asm. */
__attribute__((noinline, used)) void
port_print_alphabet(struct cpu_register_state *registers, port_u8 *memory)
{
	port_u16 hl;
	port_u16 de;
	port_u8 b;
	port_u8 c;

	/* xor a; ldh [hAutoBGTransferEnabled], a */
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;

	/* ld a, [wAlphabetCase]; and a; ld de, LowerCaseAlphabet;
	 * jr nz, .lowercase; ld de, UpperCaseAlphabet */
	if (memory[W_ALPHABET_CASE] == 0)
		de = UPPER_CASE_ALPHABET;
	else
		de = LOWER_CASE_ALPHABET;

	/* hlcoord 2, 5; lb bc, 5, 9: 5 rows, 9 columns */
	hl = (port_u16)(W_TILE_MAP + 5 * SCREEN_WIDTH + 2);
	b = 5;
	do {
		c = 9;
		do {
			/* ld a, [de]; ld [hli], a; inc hl; inc de */
			registers->a = memory[de];
			memory[hl] = registers->a;
			hl += 2;
			de++;
		} while (--c != 0);
		/* ld bc, SCREEN_WIDTH + 2; add hl, bc */
		hl += SCREEN_WIDTH + 2;
	} while (--b != 0);
	/* call PlaceString with the loop's final HL/DE/A/B/C.  Each outer
	 * iteration pushes BC and pops it back after ADD HL,BC, so the
	 * LD BC,SCREEN_WIDTH+2 never survives: C is still 9 and only B
	 * counts down to 0.  The closing DEC B leaves Z set with N set and
	 * H/C clear (the final ADD HL,BC from 0xC4B8 carries out of neither
	 * bit 11 nor bit 15), so F is exactly Z|N here. */
	registers->f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);
	registers->b = 0;
	registers->c = 9;
	registers->d = (port_u8)(de >> 8);
	registers->e = (port_u8)de;
	registers->h = (port_u8)(hl >> 8);
	registers->l = (port_u8)hl;
	port_place_string(registers, memory);

	/* ld a, 1; ldh [hAutoBGTransferEnabled], a; jp Delay3 */
	registers->a = 1;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 1;
	port_delay3(registers, memory);
}
