#include "port_state.h"

/* Ports of the SetPal_* palette-packet selection routines in
 * engine/gfx/palettes.asm. Each routine selects a palette packet by loading its
 * address into HL and the address of the destination block packet into DE, then
 * returns. The destination is later copied by the calling SetPal dispatcher. */

static __attribute__((noinline)) void
set_hl(struct cpu_register_state *state, port_u16 value)
{
	state->h = (port_u8)(value >> 8);
	state->l = (port_u8)value;
}

static __attribute__((noinline)) void
set_de(struct cpu_register_state *state, port_u16 value)
{
	state->d = (port_u8)(value >> 8);
	state->e = (port_u8)value;
}

/* SetPal_BattleBlack (engine/gfx/palettes.asm:22) */
__attribute__((noinline, used)) void
port_set_pal_battle_black(struct cpu_register_state *state)
{
	set_hl(state, 0x6448); /* PalPacket_Black */
	set_de(state, 0x61b5); /* BlkPacket_Battle */
}

/* SetPal_TownMap (engine/gfx/palettes.asm:61) */
__attribute__((noinline, used)) void
port_set_pal_town_map(struct cpu_register_state *state)
{
	set_hl(state, 0x6458); /* PalPacket_TownMap */
	set_de(state, 0x619e); /* BlkPacket_WholeScreen */
}

/* SetPal_PartyMenu (engine/gfx/palettes.asm:90) */
__attribute__((noinline, used)) void
port_set_pal_party_menu(struct cpu_register_state *state)
{
	set_hl(state, 0x6438); /* PalPacket_PartyMenu */
	set_de(state, 0xcf2e); /* wPartyMenuBlkPacket */
}

/* SetPal_Slots (engine/gfx/palettes.asm:108) */
__attribute__((noinline, used)) void
port_set_pal_slots(struct cpu_register_state *state)
{
	set_hl(state, 0x6478); /* PalPacket_Slots */
	set_de(state, 0x624f); /* BlkPacket_Slots */
}

/* SetPal_TitleScreen (engine/gfx/palettes.asm:113) */
__attribute__((noinline, used)) void
port_set_pal_title_screen(struct cpu_register_state *state)
{
	set_hl(state, 0x6488); /* PalPacket_Titlescreen */
	set_de(state, 0x628e); /* BlkPacket_Titlescreen */
}

/* SetPal_Generic (engine/gfx/palettes.asm:119) */
__attribute__((noinline, used)) void
port_set_pal_generic(struct cpu_register_state *state)
{
	set_hl(state, 0x64a8); /* PalPacket_Generic */
	set_de(state, 0x619e); /* BlkPacket_WholeScreen */
}

/* SetPal_NidorinoIntro (engine/gfx/palettes.asm:124) */
__attribute__((noinline, used)) void
port_set_pal_nidorino_intro(struct cpu_register_state *state)
{
	set_hl(state, 0x64b8); /* PalPacket_NidorinoIntro */
	set_de(state, 0x62c1); /* BlkPacket_NidorinoIntro */
}

/* SetPal_GameFreakIntro (engine/gfx/palettes.asm:129)
 * Like the other SetPal_* routines it selects a palette packet (HL) and a
 * destination block packet (DE), but it additionally records the requested
 * palette command in wDefaultPaletteCommand before returning. */
__attribute__((noinline, used)) void
port_set_pal_game_freak_intro(struct set_pal_game_freak_intro_state *state)
{
	set_hl(&state->registers, 0x64c8); /* PalPacket_GameFreakIntro */
	set_de(&state->registers, 0x63dd); /* BlkPacket_GameFreakIntro */
	state->registers.a = 0x08;        /* SET_PAL_GENERIC */
	state->default_palette_command = state->registers.a;
}
