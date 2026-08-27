#include "port_state.h"

#define H_RANDOM_ADD 0xffd3u
#define H_RANDOM_SUB 0xffd4u
#define W_MON_DATA_LOCATION 0xcc49u
#define W_PARTY_COUNT 0xd163u
#define W_NUM_BAG_ITEMS 0xd31du
#define W_PLAYER_MONEY 0xd347u
#define W_OBTAINED_BADGES 0xd356u
#define W_PLAYER_ID 0xd359u
#define W_NUM_BOX_ITEMS 0xd53au
#define W_PLAYER_COINS 0xd5a4u
#define W_GAME_PROGRESS_FLAGS 0xd5f0u
#define W_GAME_PROGRESS_FLAGS_SIZE 0x00c8u
#define W_UNUSED_PLAYER_DATA_BYTE 0xd71bu
#define W_BOX_COUNT 0xda80u

void port_random_generate(struct random_generate_state *);
void port_initialize_empty_list(struct empty_list_state *);
void port_fill_memory(struct fill_memory_state *, port_u8 *);
void port_initialize_toggleable_objects_flags(struct cpu_register_state *,
	port_u8 *);

static void
init_player_random(struct init_player_data2_state *state, port_u8 *memory,
	port_u8 sample_index)
{
	struct random_generate_state random;

	random.registers = state->registers;
	random.random_add = memory[H_RANDOM_ADD];
	random.random_sub = memory[H_RANDOM_SUB];
	random.div_first = state->div_samples[sample_index];
	random.div_second = state->div_samples[sample_index + 1];
	random.loaded_bank = state->loaded_bank;
	random.rom_bank = state->rom_bank;
	port_random_generate(&random);
	state->registers = random.registers;
	memory[H_RANDOM_ADD] = random.random_add;
	memory[H_RANDOM_SUB] = random.random_sub;
	state->loaded_bank = random.loaded_bank;
	state->rom_bank = random.rom_bank;
}

static void
init_player_empty_list(struct cpu_register_state *registers, port_u8 *memory,
	port_u16 address)
{
	struct empty_list_state list;

	registers->h = (port_u8)(address >> 8);
	registers->l = (port_u8)address;
	list.registers = *registers;
	list.first = memory[address];
	list.terminator = memory[(port_u16)(address + 1u)];
	port_initialize_empty_list(&list);
	*registers = list.registers;
	memory[address] = list.first;
	memory[(port_u16)(address + 1u)] = list.terminator;
}

/* Port of InitPlayerData2 in engine/movie/oak_speech/init_player_data.asm. */
__attribute__((noinline, used)) void
port_init_player_data2(struct init_player_data2_state *state, port_u8 *memory)
{
	struct fill_memory_state fill;

	init_player_random(state, memory, 0);
	state->registers.a = memory[H_RANDOM_SUB];
	memory[W_PLAYER_ID] = state->registers.a;
	init_player_random(state, memory, 2);
	state->registers.a = memory[H_RANDOM_ADD];
	memory[W_PLAYER_ID + 1] = state->registers.a;
	state->registers.a = 0xffu;
	memory[W_UNUSED_PLAYER_DATA_BYTE] = state->registers.a;

	init_player_empty_list(&state->registers, memory, W_PARTY_COUNT);
	init_player_empty_list(&state->registers, memory, W_BOX_COUNT);
	init_player_empty_list(&state->registers, memory, W_NUM_BAG_ITEMS);
	init_player_empty_list(&state->registers, memory, W_NUM_BOX_ITEMS);

	state->registers.h = (port_u8)((W_PLAYER_MONEY + 1u) >> 8);
	state->registers.l = (port_u8)(W_PLAYER_MONEY + 1u);
	state->registers.a = 0x30u;
	memory[W_PLAYER_MONEY + 1] = state->registers.a;
	state->registers.l--;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	memory[W_PLAYER_MONEY] = state->registers.a;
	state->registers.l++;
	state->registers.l++;
	memory[W_PLAYER_MONEY + 2] = state->registers.a;
	memory[W_MON_DATA_LOCATION] = state->registers.a;

	state->registers.h = (port_u8)(W_OBTAINED_BADGES >> 8);
	state->registers.l = (port_u8)W_OBTAINED_BADGES;
	memory[W_OBTAINED_BADGES] = state->registers.a;
	state->registers.l++;
	memory[W_OBTAINED_BADGES + 1] = state->registers.a;

	state->registers.h = (port_u8)(W_PLAYER_COINS >> 8);
	state->registers.l = (port_u8)W_PLAYER_COINS;
	memory[W_PLAYER_COINS] = state->registers.a;
	state->registers.l++;
	memory[W_PLAYER_COINS + 1] = state->registers.a;

	state->registers.h = (port_u8)(W_GAME_PROGRESS_FLAGS >> 8);
	state->registers.l = (port_u8)W_GAME_PROGRESS_FLAGS;
	state->registers.b = (port_u8)(W_GAME_PROGRESS_FLAGS_SIZE >> 8);
	state->registers.c = (port_u8)W_GAME_PROGRESS_FLAGS_SIZE;
	fill.registers = state->registers;
	fill.saved_d = state->registers.d;
	fill.saved_e = state->registers.e;
	fill.written = 0;
	port_fill_memory(&fill, memory);
	state->registers = fill.registers;

	port_initialize_toggleable_objects_flags(&state->registers, memory);
}
