#include "port_state.h"

#define W_TEXT_PREDEF_FLAG 0xcf11u
#define W_CUR_MAP 0xd35eu
#define W_CUR_MAP_TEXT_PTR 0xd36cu
#define W_NUM_SPRITES 0xd4e1u
#define W_SPRITE_INDEX 0xcf13u
#define H_TEXT_ID 0xff8cu
#define H_FRAME_COUNTER 0xffd5u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define BIT_TEXT_PREDEF 0u
#define TEXT_START_MENU 0x00u
#define TEXT_MON_FAINTED 0xd0u
#define TEXT_BLACKED_OUT 0xd1u
#define TEXT_REPEL_WORE_OFF 0xd2u
#define TEXT_SAFARI_GAME_OVER 0xd3u
#define PORT_FLAG_Z 0x80u
#define PORT_FLAG_N 0x40u
#define PORT_FLAG_H 0x20u

void port_display_text_id_init(
	struct display_text_id_init_private_state *, port_u8 *);
void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);

static port_u16
read_word(const port_u8 *memory, port_u16 address)
{
	return (port_u16)(memory[address] |
		((port_u16)memory[(port_u16)(address + 1u)] << 8));
}

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;
	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0fu) < (right & 0x0fu))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

static port_u8
shift_left_flags(port_u8 value, port_u8 *result)
{
	*result = (port_u8)(value << 1);
	return (port_u8)(((value & 0x80u) != 0u ? PORT_FLAG_C : 0u) |
		((*result == 0u) ? PORT_FLAG_Z : 0u));
}

static port_u8
add_hl_de_flags(port_u16 left, port_u16 right, port_u16 *result,
	port_u8 old_flags)
{
	port_u32 wide = (port_u32)left + (port_u32)right;
	port_u8 flags = (port_u8)(old_flags & PORT_FLAG_Z);
	if (((left & 0x0fffu) + (right & 0x0fffu)) > 0x0fffu)
		flags |= PORT_FLAG_H;
	if (wide > 0xffffu)
		flags |= PORT_FLAG_C;
	*result = (port_u16)wide;
	return flags;
}

/* Port of the bounded initialization, dictionary, and out-of-range map-text
 * prefix of DisplayTextID in home/text_script.asm.  Sprite-facing, remaining
 * text-ID, script, and shared display continuations remain separate bounds. */
__attribute__((noinline, used)) void
port_display_text_id(struct display_text_id_state *state, port_u8 *memory)
{
	struct display_text_id_init_private_state init = {0};
	port_u8 saved_bank = memory[H_LOADED_ROM_BANK];
	port_u8 saved_f = state->registers.f;
	port_u8 saved_e = state->registers.e;
	state->loaded_rom_bank = saved_bank;
	state->mapper_bank = memory[R_ROMB];

	/* farcall DisplayTextIDInit (bank 1), including its complete proven body. */
	init.registers = state->registers;
	init.registers.b = 1u;
	init.registers.h = 0x70u;
	init.registers.l = 0x96u;
	port_display_text_id_init(&init, memory);
	state->registers = init.registers;
	memory[H_LOADED_ROM_BANK] = saved_bank;
	memory[R_ROMB] = state->mapper_bank;
	state->registers.a = saved_bank;
	state->registers.f = saved_f;
	/* Bankswitch returns the caller's saved AF through BC. */
	state->registers.b = saved_bank;
	state->registers.c = saved_f;
	state->registers.e = saved_e;

	if ((memory[W_TEXT_PREDEF_FLAG] & (1u << BIT_TEXT_PREDEF)) != 0u) {
		memory[W_TEXT_PREDEF_FLAG] &= (port_u8)~(1u << BIT_TEXT_PREDEF);
	} else {
		struct switch_to_map_rom_bank_state map = {0};
		map.registers = state->registers;
		map.registers.a = memory[W_CUR_MAP];
		map.loaded_rom_bank = saved_bank;
		map.mapper_bank = state->mapper_bank;
		port_switch_to_map_rom_bank(&map);
		state->registers = map.registers;
		state->loaded_rom_bank = map.loaded_rom_bank;
		state->mapper_bank = map.mapper_bank;
		memory[H_LOADED_ROM_BANK] = map.loaded_rom_bank;
		memory[R_ROMB] = map.mapper_bank;
	}

	memory[H_FRAME_COUNTER] = 30u;
	{
		port_u16 text = read_word(memory, W_CUR_MAP_TEXT_PTR);
		state->registers.h = (port_u8)(text >> 8);
		state->registers.l = (port_u8)text;
	}
	state->registers.d = 0u;
	state->registers.a = memory[H_TEXT_ID];
	memory[W_SPRITE_INDEX] = state->registers.a;
	state->registers.f = state->registers.a == 0u ?
	    (port_u8)(PORT_FLAG_Z | PORT_FLAG_H) : 0u;
	/* The dictionary's special IDs are bounded dispatch seams.  The handler and
	 * shared continuation bodies are independently proven, so this entry
	 * records each exact compare result and leaves the callee at its boundary. */
	if (state->registers.a == TEXT_START_MENU)
		return;
	if (state->registers.a == TEXT_MON_FAINTED ||
	    state->registers.a == TEXT_BLACKED_OUT ||
	    state->registers.a == TEXT_REPEL_WORE_OFF ||
	    state->registers.a == TEXT_SAFARI_GAME_OVER)
	{
		state->registers.f = (port_u8)(PORT_FLAG_Z | PORT_FLAG_N);
		return;
	}

	/* ld a,[wNumSprites]; ld e,a; ldh a,[hSpriteIndex]; cp e; jr nc,
	 * .skipSpriteHandling.  The equal case intentionally falls through to
	 * the sprite-facing handler, so this bounded port only consumes the strict
	 * out-of-range path before the map-text lookup. */
	{
		port_u8 num_sprites = memory[W_NUM_SPRITES];
		state->registers.e = num_sprites;
		state->registers.f = compare_flags(state->registers.a, num_sprites);
		if (state->registers.a >= num_sprites &&
		    state->registers.a != num_sprites) {
			port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l);
			port_u8 index = (port_u8)(state->registers.a - 1u);
			port_u8 shifted;
			port_u8 shift_flags = shift_left_flags(index, &shifted);
			port_u16 address;
			port_u8 low;
			state->registers.e = shifted;
			state->registers.f = add_hl_de_flags(hl, shifted, &address,
				shift_flags);
			low = memory[address];
			state->registers.h = memory[(port_u16)(address + 1u)];
			state->registers.l = low;
			state->registers.a = memory[(port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l)];
			state->registers.f = (port_u8)(state->registers.f &
				(PORT_FLAG_C | PORT_FLAG_H | PORT_FLAG_Z));
			return;
		}
	}
}
