#include "port_state.h"

#define CRY_DATA 0x5446u
#define CRY_DATA_BANK 0x0eu
#define CRY_SFX_START 0x14u
#define W_FREQUENCY_MODIFIER 0xc0f1u
#define W_TEMPO_MODIFIER 0xc0f2u
#define W_BANKSWITCH_HOME_SAVED_ROM_BANK 0xcf08u
#define W_BANKSWITCH_HOME_TEMP 0xcf09u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u

void port_bankswitch_home(struct button_reset_state *);
void port_bankswitch_back(struct memory_transfer_state *);

static void
cry_bankswitch_home(struct cpu_register_state *state, port_u8 *memory)
{
	struct button_reset_state bank;

	bank.registers = *state;
	bank.memory[0] = memory[W_BANKSWITCH_HOME_TEMP];
	bank.memory[1] = memory[H_LOADED_ROM_BANK];
	bank.memory[2] = memory[W_BANKSWITCH_HOME_SAVED_ROM_BANK];
	bank.memory[3] = memory[R_ROMB];
	port_bankswitch_home(&bank);
	*state = bank.registers;
	memory[W_BANKSWITCH_HOME_TEMP] = bank.memory[0];
	memory[H_LOADED_ROM_BANK] = bank.memory[1];
	memory[W_BANKSWITCH_HOME_SAVED_ROM_BANK] = bank.memory[2];
	memory[R_ROMB] = bank.memory[3];
}

static void
cry_bankswitch_back(struct cpu_register_state *state, port_u8 *memory)
{
	struct memory_transfer_state bank;

	bank.registers = *state;
	bank.memory[0] = memory[W_BANKSWITCH_HOME_SAVED_ROM_BANK];
	bank.memory[1] = memory[H_LOADED_ROM_BANK];
	bank.memory[2] = memory[R_ROMB];
	port_bankswitch_back(&bank);
	*state = bank.registers;
	memory[H_LOADED_ROM_BANK] = bank.memory[1];
	memory[R_ROMB] = bank.memory[2];
}

static void
cry_add(struct cpu_register_state *state, port_u8 value)
{
	port_u8 left = state->a;
	port_u16 result = (port_u16)left + value;

	state->a = (port_u8)result;
	state->f = 0;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	if ((left & 0x0fu) + (value & 0x0fu) > 0x0fu)
		state->f |= PORT_FLAG_H;
	if (result > 0xffu)
		state->f |= PORT_FLAG_C;
}

static void
cry_add_hl_bc(struct cpu_register_state *state)
{
	port_u16 left = (port_u16)(((port_u16)state->h << 8) | state->l);
	port_u16 right = (port_u16)(((port_u16)state->b << 8) | state->c);
	port_u32 result = (port_u32)left + right;

	state->h = (port_u8)(result >> 8);
	state->l = (port_u8)result;
	state->f &= PORT_FLAG_Z;
	if ((left & 0x0fffu) + (right & 0x0fffu) > 0x0fffu)
		state->f |= PORT_FLAG_H;
	if (result > 0xffffu)
		state->f |= PORT_FLAG_C;
}

/* Port of GetCryData in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_get_cry_data(struct cpu_register_state *state, port_u8 *memory)
{
	port_u16 pointer;
	port_u8 old = state->a;

	state->a--;
	state->f = (port_u8)((state->f & PORT_FLAG_C) | PORT_FLAG_N |
		(state->a == 0 ? PORT_FLAG_Z : 0) |
		((old & 0x0fu) == 0 ? PORT_FLAG_H : 0));
	state->c = state->a;
	state->b = 0;
	state->h = (port_u8)(CRY_DATA >> 8);
	state->l = (port_u8)CRY_DATA;
	cry_add_hl_bc(state);
	cry_add_hl_bc(state);
	cry_add_hl_bc(state);
	pointer = (port_u16)(((port_u16)state->h << 8) | state->l);
	state->a = CRY_DATA_BANK;
	cry_bankswitch_home(state, memory);
	state->a = memory[pointer++];
	state->h = (port_u8)(pointer >> 8);
	state->l = (port_u8)pointer;
	state->b = state->a;
	state->a = memory[pointer++];
	state->h = (port_u8)(pointer >> 8);
	state->l = (port_u8)pointer;
	memory[W_FREQUENCY_MODIFIER] = state->a;
	state->a = memory[pointer];
	memory[W_TEMPO_MODIFIER] = state->a;
	cry_bankswitch_back(state, memory);
	state->a = state->b;
	state->c = CRY_SFX_START;
	state->f = (port_u8)((state->a & 0x80u) ? PORT_FLAG_C : 0);
	state->a = (port_u8)((state->a << 1) | (state->a >> 7));
	cry_add(state, state->b);
	cry_add(state, state->c);
}
