#include "port_state.h"

#define W_SHADOW_OAM ((port_u16)0xc300u)
#define W_SAVED_OAM ((port_u16)0xcc5bu)
#define W_OAM_BASE_TILE ((port_u16)0xcd5bu)
#define W_SYM_ATTRS ((port_u16)0xcd5cu)
#define W_SPECIES ((port_u16)0xcd5du)
#define W_POKEDEX_NUM ((port_u16)0xd11eu)
#define H_PARTY_MON_INDEX ((port_u16)0xff8cu)
#define ICON_HELIX_TILE ((port_u8)0x08u)
#define OAM_COPY_LENGTH ((port_u16)0x0060u)

struct write_party_oam_species_private_state {
	struct cpu_register_state registers;
	port_u8 mon_species;
	port_u8 party_index;
	port_u8 sprite_id;
	port_u8 pokedex_num;
	port_u8 sprite_flags;
};

void port_write_symmetric_mon_party_sprite_oam(
	struct symmetric_oam_state *state);
void port_write_asymmetric_mon_party_sprite_oam(
	struct asymmetric_oam_state *state);
void port_copy_data(struct cpu_register_state *state, port_u8 *memory);

/* Port of WriteMonPartySpriteOAMBySpecies plus the WriteMonPartySpriteOAM
 * fallthrough in engine/gfx/mon_icons.asm.
 *
 * The sprite-ID lookup itself (GetPartyMonSpriteID through its predef
 * IndexToPokedex dispatch) stays behind the proof's compositional
 * boundary: the sprite ID, the wPokedexNum effect, and the lookup exit
 * flags arrive as inputs. Everything after the lookup -- the
 * wOAMBaseTile store, the first-frame OAM pointer setup, the helix tile
 * selection, the symmetric/asymmetric OAM writes, and the saved-OAM
 * continuation -- executes through the real proven callee ports.
 */
__attribute__((noinline, used)) void
port_write_mon_party_sprite_oam_by_species_private(
	struct write_party_oam_species_private_state *state, port_u8 *memory)
{
	struct symmetric_oam_state symmetric;
	struct asymmetric_oam_state asymmetric;
	struct cpu_register_state *registers = &state->registers;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 index;
	port_u8 i;

	/* xor a; ldh [hPartyMonIndex], a */
	registers->a = 0;
	registers->f = PORT_FLAG_Z;
	memory[H_PARTY_MON_INDEX] = 0;
	state->party_index = 0;

	/* ld a, [wMonPartySpriteSpecies] */
	registers->a = memory[W_SPECIES];

	/* call GetPartyMonSpriteID: compositional boundary inputs. */
	memory[W_POKEDEX_NUM] = state->pokedex_num;
	registers->a = state->sprite_id;
	registers->f = state->sprite_flags;

	/* ld [wOAMBaseTile], a */
	memory[W_OAM_BASE_TILE] = registers->a;

	/* jr WriteMonPartySpriteOAM: push af */
	saved_a = registers->a;
	saved_f = registers->f;

	/* ld c, $10; ld h, HIGH(wShadowOAM) */
	registers->c = 0x10;
	registers->h = (port_u8)(W_SHADOW_OAM >> 8);

	/* ldh a, [hPartyMonIndex]; swap a; ld l, a */
	index = memory[H_PARTY_MON_INDEX];
	index = (port_u8)((port_u8)(index << 4) | (port_u8)(index >> 4));
	registers->a = index;
	registers->l = index;
	registers->f = (index == 0) ? PORT_FLAG_Z : 0;

	/* add $10; ld b, a: the immediate's low nibble is zero, so the
	 * half-carry never fires. */
	{
		port_u8 left = index;
		port_u16 wide = (port_u16)left + 0x10u;
		registers->a = (port_u8)wide;
		registers->f = 0;
		if (registers->a == 0)
			registers->f |= PORT_FLAG_Z;
		if (((left & 0x0f) + 0x00) > 0x0f)
			registers->f |= PORT_FLAG_H;
		if (wide > 0xff)
			registers->f |= PORT_FLAG_C;
	}
	registers->b = registers->a;

	/* pop af */
	registers->a = saved_a;
	registers->f = saved_f;

	/* cp ICON_HELIX << 2 */
	{
		port_u8 left = registers->a;
		registers->f = PORT_FLAG_N;
		if (left == ICON_HELIX_TILE)
			registers->f |= PORT_FLAG_Z;
		if ((left & 0x0f) < (ICON_HELIX_TILE & 0x0f))
			registers->f |= PORT_FLAG_H;
		if (left < ICON_HELIX_TILE)
			registers->f |= PORT_FLAG_C;
	}

	if (registers->a == ICON_HELIX_TILE) {
		asymmetric.registers.h = registers->h;
		asymmetric.registers.l = registers->l;
		asymmetric.registers.b = registers->b;
		asymmetric.registers.c = registers->c;
		asymmetric.registers.d = registers->d;
		asymmetric.registers.e = registers->e;
		asymmetric.registers.a = registers->a;
		asymmetric.registers.f = registers->f;
		asymmetric.base_tile = memory[W_OAM_BASE_TILE];
		for (i = 0; i < 16; i++)
			asymmetric.output[i] =
				memory[(port_u16)(W_SHADOW_OAM + i)];
		port_write_asymmetric_mon_party_sprite_oam(&asymmetric);
		*registers = asymmetric.registers;
		memory[W_OAM_BASE_TILE] = asymmetric.base_tile;
		for (i = 0; i < 16; i++)
			memory[(port_u16)(W_SHADOW_OAM + i)] =
				asymmetric.output[i];
	} else {
		symmetric.registers.h = registers->h;
		symmetric.registers.l = registers->l;
		symmetric.registers.b = registers->b;
		symmetric.registers.c = registers->c;
		symmetric.registers.d = registers->d;
		symmetric.registers.e = registers->e;
		symmetric.registers.a = registers->a;
		symmetric.registers.f = registers->f;
		symmetric.base_tile = memory[W_OAM_BASE_TILE];
		symmetric.attributes = memory[W_SYM_ATTRS];
		for (i = 0; i < 16; i++)
			symmetric.output[i] =
				memory[(port_u16)(W_SHADOW_OAM + i)];
		port_write_symmetric_mon_party_sprite_oam(&symmetric);
		*registers = symmetric.registers;
		memory[W_OAM_BASE_TILE] = symmetric.base_tile;
		memory[W_SYM_ATTRS] = symmetric.attributes;
		for (i = 0; i < 16; i++)
			memory[(port_u16)(W_SHADOW_OAM + i)] =
				symmetric.output[i];
	}

	/* .makeCopy: ld hl, wShadowOAM; ld de, wMonPartySpritesSavedOAM;
	 * ld bc, OBJ_SIZE * 4 * PARTY_LENGTH; jp CopyData */
	registers->h = (port_u8)(W_SHADOW_OAM >> 8);
	registers->l = (port_u8)W_SHADOW_OAM;
	registers->d = (port_u8)(W_SAVED_OAM >> 8);
	registers->e = (port_u8)W_SAVED_OAM;
	registers->b = (port_u8)(OAM_COPY_LENGTH >> 8);
	registers->c = (port_u8)OAM_COPY_LENGTH;
	port_copy_data(registers, memory);
}
