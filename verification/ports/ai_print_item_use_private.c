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

#define AIPIU_W_AI_COUNT 0xccdfu
#define AIPIU_W_AI_ITEM 0xcf05u

void port_ai_print_item_use_(struct get_name_state *state, port_u8 *memory);
void port_decrement_ai_count(struct ai_count_state *state);

/* Port of AIPrintItemUse in engine/battle/trainer_ai.asm. */
__attribute__((noinline, used)) void
port_ai_print_item_use(struct get_name_state *state, port_u8 *memory)
{
	struct ai_count_state count_state;

	memory[AIPIU_W_AI_ITEM] = state->registers.a;
	port_ai_print_item_use_(state, memory);
	count_state.registers = state->registers;
	count_state.ai_count = memory[AIPIU_W_AI_COUNT];
	port_decrement_ai_count(&count_state);
	state->registers = count_state.registers;
	memory[AIPIU_W_AI_COUNT] = count_state.ai_count;
}
