#include "port_state.h"

#define R_ROMB 0x2000u
#define S_SPRITE_BUFFER0 0xa000u
#define S_SPRITE_BUFFER1 0xa188u
#define V_FRONT_PIC 0x9000u
#define W_PREDEF_ID 0xcc4eu
#define W_PREDEF_HL 0xcc4fu
#define W_PREDEF_DE 0xcc51u
#define W_PREDEF_BC 0xcc53u
#define W_PREDEF_PARENT_BANK 0xcf12u
#define W_SPRITE_FLIPPED 0xd0aau
#define W_PREDEF_BANK 0xd0b7u
#define H_START_TILE_ID 0xffe1u
#define H_LOADED_ROM_BANK 0xffb8u

#define COPY_UNCOMPRESSED_PIC_PREDEF_ID 1u
#define PREDEF_POINTERS_BANK 0x13u
#define COPY_UNCOMPRESSED_PIC_BANK 0x0fu
#define COPY_UNCOMPRESSED_PIC_LOW 0xc6u
#define COPY_UNCOMPRESSED_PIC_HIGH 0x70u

void port_uncompress_sprite_from_de(struct cpu_register_state *, port_u8 *);
void port_copy_data(struct cpu_register_state *, port_u8 *);
void port_interlace_merge_sprite_buffers(struct cpu_register_state *, port_u8 *);
void port_get_predef_pointer(struct predef_pointer_state *);
void port_copy_uncompressed_pic_to_tilemap(
	struct uncompressed_pic_copy_state *);

static void
store_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
apply_pic_writes(const struct uncompressed_pic_copy_state *state,
	port_u8 *memory, port_u16 base, port_u8 flipped)
{
	port_u8 column;
	port_u8 row;
	port_u8 index = 0;

	for (column = 0; column < 7; column++) {
		port_u16 column_address = flipped == 0
			? (port_u16)(base + column)
			: (port_u16)(base + 6u - column);

		for (row = 0; row < 7; row++) {
			port_u16 address = (port_u16)(column_address + 20u * row);

			memory[address] = state->writes[index++];
		}
	}
}

/* Port of IntroDisplayPicCenteredOrUpperRight in oak_speech.asm. */
__attribute__((noinline, used)) void
port_intro_display_pic_centered_or_upper_right(
	struct uncompressed_pic_copy_state *state, port_u8 *memory)
{
	struct predef_pointer_state pointer;
	port_u8 saved_b = state->registers.b;
	port_u8 saved_c = state->registers.c;
	port_u8 parent_bank;
	port_u8 pushed_f;
	port_u8 flipped;
	port_u16 destination;

	state->registers.a = state->registers.b;
	port_uncompress_sprite_from_de(&state->registers, memory);

	store_pair(&state->registers.h, &state->registers.l,
		S_SPRITE_BUFFER1);
	store_pair(&state->registers.d, &state->registers.e,
		S_SPRITE_BUFFER0);
	store_pair(&state->registers.b, &state->registers.c, 0x0310u);
	port_copy_data(&state->registers, memory);

	store_pair(&state->registers.d, &state->registers.e, V_FRONT_PIC);
	port_interlace_merge_sprite_buffers(&state->registers, memory);

	state->registers.b = saved_b;
	state->registers.c = saved_c;
	destination = saved_c == 0 ? 0xc3f6u : 0xc3c3u;
	store_pair(&state->registers.h, &state->registers.l, destination);
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	memory[H_START_TILE_ID] = 0;

	/* predef_jump CopyUncompressedPicToTilemap */
	memory[W_PREDEF_ID] = COPY_UNCOMPRESSED_PIC_PREDEF_ID;
	parent_bank = memory[H_LOADED_ROM_BANK];
	memory[W_PREDEF_PARENT_BANK] = parent_bank;
	pushed_f = state->registers.f;
	state->registers.a = PREDEF_POINTERS_BANK;
	memory[H_LOADED_ROM_BANK] = PREDEF_POINTERS_BANK;
	memory[R_ROMB] = PREDEF_POINTERS_BANK;

	pointer.registers = state->registers;
	pointer.predef_id = COPY_UNCOMPRESSED_PIC_PREDEF_ID;
	pointer.fetched_bank = COPY_UNCOMPRESSED_PIC_BANK;
	pointer.fetched_pointer_low = COPY_UNCOMPRESSED_PIC_LOW;
	pointer.fetched_pointer_high = COPY_UNCOMPRESSED_PIC_HIGH;
	port_get_predef_pointer(&pointer);
	state->registers = pointer.registers;
	memory[W_PREDEF_HL] = pointer.saved_h;
	memory[W_PREDEF_HL + 1] = pointer.saved_l;
	memory[W_PREDEF_DE] = pointer.saved_d;
	memory[W_PREDEF_DE + 1] = pointer.saved_e;
	memory[W_PREDEF_BC] = pointer.saved_b;
	memory[W_PREDEF_BC + 1] = pointer.saved_c;
	memory[W_PREDEF_BANK] = pointer.predef_bank;

	state->registers.a = memory[W_PREDEF_BANK];
	memory[H_LOADED_ROM_BANK] = state->registers.a;
	memory[R_ROMB] = state->registers.a;
	state->registers.d = 0x3e;
	state->registers.e = 0x8d;

	flipped = memory[W_SPRITE_FLIPPED];
	state->sprite_flipped = flipped;
	state->predef_h = memory[W_PREDEF_HL];
	state->predef_l = memory[W_PREDEF_HL + 1];
	state->start_tile_id = memory[H_START_TILE_ID];
	port_copy_uncompressed_pic_to_tilemap(state);
	apply_pic_writes(state, memory, destination, flipped);

	state->registers.a = parent_bank;
	state->registers.f = pushed_f;
	memory[H_LOADED_ROM_BANK] = parent_bank;
	memory[R_ROMB] = parent_bank;
}
