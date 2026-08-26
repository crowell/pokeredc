#include "port_state.h"

/* Port of PrepareOakSpeech in engine/movie/oak_speech/oak_speech.asm:
 *
 *   ld a, [wLetterPrintingDelayFlags] / push af
 *   ld a, [wOptions] / push af
 *   ld a, [wStatusFlags6] / push af
 *   ld hl, wPlayerName / ld bc, wBoxDataEnd - wPlayerName
 *   xor a / call FillMemory          ; proven (real fill loop)
 *   ld hl, wSpriteDataStart / ld bc, wSpriteDataEnd - wSpriteDataStart
 *   xor a / call FillMemory          ; proven (real fill loop)
 *   pop af / ld [wStatusFlags6], a
 *   pop af / ld [wOptions], a
 *   pop af / ld [wLetterPrintingDelayFlags], a
 *   ld a, [wOptionsInitialized] / and a / call z, InitOptions ; proven
 *   ld hl, DebugNewGamePlayerName / ld de, wPlayerName
 *   ld bc, NAME_LENGTH / call CopyData ; proven (real copy loop)
 *   ld hl, DebugNewGameRivalName / ld de, wRivalName
 *   ld bc, NAME_LENGTH / jp CopyData ; proven tail callee
 *
 * Zeroes the player/sprite data regions, restores the three saved option
 * bytes, initializes the options when unset, and installs the debug
 * NINTEN/SONY names for the new-game intro. */

void port_fill_memory(struct fill_memory_state *, port_u8 *);
void port_init_options(struct init_options_state *);
void port_copy_data(struct cpu_register_state *, port_u8 *);

#define W_LETTER_PRINTING_DELAY_FLAGS 0xd358u
#define W_OPTIONS 0xd355u
#define W_STATUS_FLAGS6 0xd732u
#define W_PLAYER_NAME 0xd158u
#define PLAYER_NAME_FILL_SIZE 0x0d8au
#define W_SPRITE_DATA_START 0xc100u
#define SPRITE_DATA_FILL_SIZE 0x0200u
#define W_OPTIONS_INITIALIZED 0xd08au
#define DEBUG_NEW_GAME_PLAYER_NAME 0x45aau
#define DEBUG_NEW_GAME_RIVAL_NAME 0x45b1u
#define W_RIVAL_NAME 0xd34au
#define NAME_LENGTH 11u

__attribute__((noinline, used)) void
port_prepare_oak_speech(struct cpu_register_state *state, port_u8 *memory)
{
	struct cpu_register_state entry = *state;
	port_u8 lpdf = memory[W_LETTER_PRINTING_DELAY_FLAGS];
	port_u8 options = memory[W_OPTIONS];
	port_u8 status6 = memory[W_STATUS_FLAGS6];

	{
		struct fill_memory_state fm;

		fm.registers = *state;
		fm.registers.h = (port_u8)(W_PLAYER_NAME >> 8);
		fm.registers.l = (port_u8)(W_PLAYER_NAME & 0xff);
		fm.registers.b = (port_u8)(PLAYER_NAME_FILL_SIZE >> 8);
		fm.registers.c = (port_u8)(PLAYER_NAME_FILL_SIZE & 0xff);
		fm.registers.a = 0;
		fm.saved_d = entry.d;
		fm.saved_e = entry.e;
		fm.written = 0;
		port_fill_memory(&fm, memory);
	}
	{
		struct fill_memory_state fm;

		fm.registers = *state;
		fm.registers.h = (port_u8)(W_SPRITE_DATA_START >> 8);
		fm.registers.l = (port_u8)(W_SPRITE_DATA_START & 0xff);
		fm.registers.b = (port_u8)(SPRITE_DATA_FILL_SIZE >> 8);
		fm.registers.c = (port_u8)(SPRITE_DATA_FILL_SIZE & 0xff);
		fm.registers.a = 0;
		fm.saved_d = entry.d;
		fm.saved_e = entry.e;
		fm.written = 0;
		port_fill_memory(&fm, memory);
	}

	memory[W_STATUS_FLAGS6] = status6;
	memory[W_OPTIONS] = options;
	memory[W_LETTER_PRINTING_DELAY_FLAGS] = lpdf;

	if (memory[W_OPTIONS_INITIALIZED] == 0) {
		struct init_options_state io;

		io.registers = *state;
		port_init_options(&io);
		memory[W_LETTER_PRINTING_DELAY_FLAGS] =
		    io.letter_printing_delay_flags;
		memory[W_OPTIONS] = io.options;
	}

	{
		struct cpu_register_state work = entry;

		work.h = (port_u8)(DEBUG_NEW_GAME_PLAYER_NAME >> 8);
		work.l = (port_u8)(DEBUG_NEW_GAME_PLAYER_NAME & 0xff);
		work.d = (port_u8)(W_PLAYER_NAME >> 8);
		work.e = (port_u8)(W_PLAYER_NAME & 0xff);
		work.b = (port_u8)(NAME_LENGTH >> 8);
		work.c = (port_u8)(NAME_LENGTH & 0xff);
		port_copy_data(&work, memory);
	}
	{
		struct cpu_register_state work = entry;

		work.h = (port_u8)(DEBUG_NEW_GAME_RIVAL_NAME >> 8);
		work.l = (port_u8)(DEBUG_NEW_GAME_RIVAL_NAME & 0xff);
		work.d = (port_u8)(W_RIVAL_NAME >> 8);
		work.e = (port_u8)(W_RIVAL_NAME & 0xff);
		work.b = (port_u8)(NAME_LENGTH >> 8);
		work.c = (port_u8)(NAME_LENGTH & 0xff);
		port_copy_data(&work, memory);
	}
	/* Exit through the tail CopyData: its proven loop-exit leaves
	 * A := last source byte, F := Z, BC := 0, HL := source end, and
	 * DE := destination end. */
	state->a = memory[DEBUG_NEW_GAME_RIVAL_NAME + NAME_LENGTH - 1u];
	state->f = PORT_FLAG_Z;
	state->b = 0u;
	state->c = 0u;
	state->h = (port_u8)((DEBUG_NEW_GAME_RIVAL_NAME + NAME_LENGTH) >> 8);
	state->l = (port_u8)((DEBUG_NEW_GAME_RIVAL_NAME + NAME_LENGTH) & 0xffu);
	state->d = (port_u8)((W_RIVAL_NAME + NAME_LENGTH) >> 8);
	state->e = (port_u8)((W_RIVAL_NAME + NAME_LENGTH) & 0xffu);
}
