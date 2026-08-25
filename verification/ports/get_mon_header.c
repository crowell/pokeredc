#include "port_state.h"

/* Port of GetMonHeader in home/pokemon.asm:
 *
 *   ldh a, [hLoadedROMBank] / push af
 *   ld a, BANK(BaseStats) / ldh [hLoadedROMBank], a / ld [rROMB], a
 *   push bc / push de / push hl
 *   ld a, [wPokedexNum] / push af
 *   ld a, [wCurSpecies] / ld [wPokedexNum], a
 *   ld de, FossilKabutopsPic / ld b, $66 / cp FOSSIL_KABUTOPS / jr z, .specialID
 *   ld de, GhostPic / cp MON_GHOST / jr z, .specialID
 *   ld de, FossilAerodactylPic / ld b, $77 / cp FOSSIL_AERODACTYL / jr z, .specialID
 *   cp MEW / jr z, .mew
 *   predef IndexToPokedex            ; proven
 *   ld a, [wPokedexNum] / dec a
 *   ld bc, BASE_DATA_SIZE / ld hl, BaseStats
 *   call AddNTimes                   ; proven
 *   ld de, wMonHeader / ld bc, BASE_DATA_SIZE / call CopyData ; proven
 *   jr .done
 * .specialID:
 *   ld hl, wMonHSpriteDim / ld [hl], b / inc hl / ld [hl], e / inc hl / ld [hl], d
 *   jr .done
 * .mew:
 *   ld hl, MewBaseStats / ld de, wMonHeader / ld bc, BASE_DATA_SIZE
 *   ld a, BANK(MewBaseStats) / call FarCopyData ; proven
 * .done:
 *   ld a, [wCurSpecies] / ld [wMonHIndex], a
 *   pop af / ld [wPokedexNum], a / pop hl / pop de / pop bc / pop af
 *   ldh [hLoadedROMBank], a / ld [rROMB], a / ret
 *
 * The IndexToPokedex composition supplies the ordering-table byte through the
 * proven port's `fetched` input (the embedded table below is byte-verified
 * against ROM in the proof). The pops restore every entry register, so the
 * saved set is written back verbatim at the exit; A ends as wCurSpecies. */

void port_index_to_pokedex(struct indexed_load_state *);
void port_add_n_times(struct cpu_register_state *);
void port_copy_data(struct cpu_register_state *, port_u8 *);
void port_far_copy_data(struct far_copy_data_state *, port_u8 *);

#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define BANK_BASE_STATS 0x0eu
#define W_POKEDEX_NUM 0xd11eu
#define W_CUR_SPECIES 0xd0b5u
#define FOSSIL_KABUTOPS 0xb6u
#define MON_GHOST 0xb8u
#define FOSSIL_AERODACTYL 0xb7u
#define MEW 0x15u
#define BASE_DATA_SIZE 0x1cu
#define BASE_STATS_HL 0x43deu
#define W_MON_HEADER 0xd0b8u
#define W_MON_H_SPRITE_DIM 0xd0c2u
#define BANK_MEW_BASE_STATS 0x01u
#define CURRENT_BANK 0x03u

static const port_u8 pokedex_order_table[190] = {
    0x70,0x73,0x20,0x23,0x15,0x64,0x22,0x50,0x02,0x67,0x6c,0x66,0x58,0x5e,0x1d,0x1f,
    0x68,0x6f,0x83,0x3b,0x97,0x82,0x5a,0x48,0x5c,0x7b,0x78,0x09,0x7f,0x72,0x00,0x00,
    0x3a,0x5f,0x16,0x10,0x4f,0x40,0x4b,0x71,0x43,0x7a,0x6a,0x6b,0x18,0x2f,0x36,0x60,
    0x4c,0x00,0x7e,0x00,0x7d,0x52,0x6d,0x00,0x38,0x56,0x32,0x80,0x00,0x00,0x00,0x53,
    0x30,0x95,0x00,0x00,0x00,0x54,0x3c,0x7c,0x92,0x90,0x91,0x84,0x34,0x62,0x00,0x00,
    0x00,0x25,0x26,0x19,0x1a,0x00,0x00,0x93,0x94,0x8c,0x8d,0x74,0x75,0x00,0x00,0x1b,
    0x1c,0x8a,0x8b,0x27,0x28,0x85,0x88,0x87,0x86,0x42,0x29,0x17,0x2e,0x3d,0x3e,0x0d,
    0x0e,0x0f,0x00,0x55,0x39,0x33,0x31,0x57,0x00,0x00,0x0a,0x0b,0x0c,0x44,0x00,0x37,
    0x61,0x2a,0x96,0x8f,0x81,0x00,0x00,0x59,0x00,0x63,0x5b,0x00,0x65,0x24,0x6e,0x35,
    0x69,0x00,0x5d,0x3f,0x41,0x11,0x12,0x79,0x01,0x03,0x49,0x00,0x76,0x77,0x00,0x00,
    0x00,0x00,0x4d,0x4e,0x13,0x14,0x21,0x1e,0x4a,0x89,0x8e,0x00,0x51,0x00,0x00,0x04,
    0x07,0x05,0x08,0x06,0x00,0x00,0x00,0x00,0x2b,0x2c,0x2d,0x45,0x46,0x47
};

__attribute__((noinline, used)) void
port_get_mon_header(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_dex = memory[W_POKEDEX_NUM];
	port_u8 species = memory[W_CUR_SPECIES];

	memory[H_LOADED_ROM_BANK] = BANK_BASE_STATS;
	memory[R_ROMB] = BANK_BASE_STATS;
	memory[W_POKEDEX_NUM] = species;

	if (species == FOSSIL_KABUTOPS || species == MON_GHOST ||
	    species == FOSSIL_AERODACTYL) {
		port_u8 dim;
		port_u8 ptr_lo;
		port_u8 ptr_hi;

		if (species == FOSSIL_KABUTOPS) {
			dim = 0x66u;
			ptr_lo = 0xe8u;
			ptr_hi = 0x79u;
		} else if (species == MON_GHOST) {
			dim = 0x66u;
			ptr_lo = 0xb5u;
			ptr_hi = 0x66u;
		} else {
			dim = 0x77u;
			ptr_lo = 0x36u;
			ptr_hi = 0x65u;
		}
		memory[W_MON_H_SPRITE_DIM] = dim;
		memory[W_MON_H_SPRITE_DIM + 1] = ptr_lo;
		memory[W_MON_H_SPRITE_DIM + 2] = ptr_hi;
	} else if (species == MEW) {
		struct far_copy_data_state fc;

		fc.registers.h = (port_u8)(0x425bu >> 8);
		fc.registers.l = (port_u8)(0x425bu & 0xff);
		fc.registers.d = (port_u8)(W_MON_HEADER >> 8);
		fc.registers.e = (port_u8)(W_MON_HEADER & 0xff);
		fc.registers.b = (port_u8)(BASE_DATA_SIZE >> 8);
		fc.registers.c = (port_u8)(BASE_DATA_SIZE & 0xff);
		fc.registers.a = BANK_MEW_BASE_STATS;
		/* F from the taken `cp MEW`: Z set, N set, H/C clear */
		fc.registers.f = PORT_FLAG_Z | PORT_FLAG_N;
		fc.requested_bank = BANK_MEW_BASE_STATS;
		fc.loaded_bank = CURRENT_BANK;
		fc.rom_bank = CURRENT_BANK;
		port_far_copy_data(&fc, memory);
	} else {
		struct indexed_load_state ix;

		ix = (struct indexed_load_state){entry, species,
		    pokedex_order_table[species - 1u]};
		port_index_to_pokedex(&ix);
		memory[W_POKEDEX_NUM] = ix.fetched;

		{
			struct cpu_register_state work = entry;

			/* the `cp MEW` before the jump leaves N set with H/C from the
			 * comparison; `dec a` then preserves that carry */
			work.f = (port_u8)(PORT_FLAG_N |
			    (((species & 0x0f) < (MEW & 0x0f)) ? PORT_FLAG_H : 0) |
			    ((species < MEW) ? PORT_FLAG_C : 0));
			work.a = (port_u8)(ix.fetched - 1u);
			work.h = (port_u8)(BASE_STATS_HL >> 8);
			work.l = (port_u8)(BASE_STATS_HL & 0xff);
			work.b = (port_u8)(BASE_DATA_SIZE >> 8);
			work.c = (port_u8)(BASE_DATA_SIZE & 0xff);
			port_add_n_times(&work);
			work.d = (port_u8)(W_MON_HEADER >> 8);
			work.e = (port_u8)(W_MON_HEADER & 0xff);
			work.b = (port_u8)(BASE_DATA_SIZE >> 8);
			work.c = (port_u8)(BASE_DATA_SIZE & 0xff);
			port_copy_data(&work, memory);
		}
	}

	memory[W_MON_HEADER] = species; /* wMonHIndex */
	memory[W_POKEDEX_NUM] = saved_dex;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = saved_bank;
	/* the second `pop af` restores the saved bank byte into A (pushed right
	 * after `ldh a, [hLoadedROMBank]`) together with the entry F */
	*state = entry;
	state->a = saved_bank;
}
