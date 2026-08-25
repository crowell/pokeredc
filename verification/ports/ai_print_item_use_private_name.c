#include "port_state.h"

struct get_name_state {
	struct cpu_register_state registers;
	port_u8 name_list_index;
	port_u8 name_list_type;
	port_u8 predef_bank;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
	port_u8 swap_temp;
	port_u8 swap_temp_plus1;
	port_u8 unused_pointer_low;
	port_u8 unused_pointer_high;
	struct cpu_register_state saved;
	port_u8 saved_bank;
};

#define AIPIU_W_AI_ITEM 0xcf05u
#define AIPIU_W_NAMED_OBJECT_INDEX 0xd11eu
#define AIPIU_BATTLE_USE_ITEM_TEXT 0x6844u

void port_get_item_name(struct get_name_state *state, port_u8 *memory);
void port_print_text(struct cpu_register_state *state, port_u8 *memory);

/* Port of AIPrintItemUse_ in engine/battle/trainer_ai.asm. */
__attribute__((noinline, used)) void
port_ai_print_item_use_(struct get_name_state *state, port_u8 *memory)
{
	state->registers.a = memory[AIPIU_W_AI_ITEM];
	state->named_object_index = state->registers.a;
	memory[AIPIU_W_NAMED_OBJECT_INDEX] = state->registers.a;
	port_get_item_name(state, memory);
	state->registers.h = (port_u8)(AIPIU_BATTLE_USE_ITEM_TEXT >> 8);
	state->registers.l = (port_u8)AIPIU_BATTLE_USE_ITEM_TEXT;
	port_print_text(&state->registers, memory);
}
