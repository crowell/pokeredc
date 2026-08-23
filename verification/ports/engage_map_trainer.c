#include "port_state.h"

/* Port of EngageMapTrainer in home/trainers.asm:
 *
 *   ld hl, wMapSpriteExtraData      ; $d504
 *   ld d, 0
 *   ld a, [wSpriteIndex]            ; $cf13
 *   dec a                           ; sprite indices are 1-based
 *   add a                           ; two bytes per trainer entry
 *   ld e, a
 *   add hl, de
 *   ld a, [hli]
 *   ld [wEngagedTrainerClass], a    ; $cd2d
 *   ld a, [hl]
 *   ld [wEngagedTrainerSet], a      ; $cd2e
 *   jp PlayTrainerMusic             ; proven tail composition
 */

void port_play_trainer_music(struct cpu_register_state *, port_u8 *);

#define W_MAP_SPRITE_EXTRA_DATA 0xd504u
#define W_SPRITE_INDEX          0xcf13u
#define W_ENGAGED_TRAINER_CLASS 0xcd2du
#define W_ENGAGED_TRAINER_SET   0xcd2eu

__attribute__((noinline, used)) void
port_engage_map_trainer(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 hl = W_MAP_SPRITE_EXTRA_DATA;
	port_u8 index = memory[W_SPRITE_INDEX];
	port_u16 de;

	/* dec a: N set, Z iff index was 1, H iff low nibble was 0. */
	index--;
	state->f = (port_u8)(PORT_FLAG_N |
			     ((index == 0) ? PORT_FLAG_Z : 0) |
			     (((index & 0x0fu) == 0x00u) ? PORT_FLAG_H : 0));

	/* add a: Z iff doubled == 0, H iff nibble carry out, C iff overflow,
	 * N clear. */
	de = (port_u16)(index << 1);
	state->f = (port_u8)(((de == 0) ? PORT_FLAG_Z : 0) |
			     (((index & 0x0fu) > 0x07u) ? PORT_FLAG_H : 0) |
			     ((index >= 0x80u) ? PORT_FLAG_C : 0));
	state->e = (port_u8)de;

	/* add hl, de: N clear, Z preserved, H/C per 16-bit addition. */
	{
		port_u16 result = (port_u16)(hl + de);
		port_u8 f = (port_u8)(state->f & PORT_FLAG_Z);
		if ((hl & 0x000fu) + (de & 0x000fu) > 0x000fu)
			f |= PORT_FLAG_H;
		if ((int)hl + (int)de > 0xffff)
			f |= PORT_FLAG_C;
		hl = result;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		state->f = f;
	}

	/* ld a, [hli]; ld [wEngagedTrainerClass], a
	 * ld a, [hl];  ld [wEngagedTrainerSet], a */
	state->a = memory[hl];
	memory[W_ENGAGED_TRAINER_CLASS] = state->a;
	state->a = memory[hl + 1];
	memory[W_ENGAGED_TRAINER_SET] = state->a;

	/* jp PlayTrainerMusic (tail call into the proven port) */
	port_play_trainer_music(state, memory);
}
