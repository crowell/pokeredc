#include "port_state.h"

#define OAKS_PARCEL 0x46u
#define W_NUM_BAG_ITEMS 0xd31du
#define W_BAG_ITEMS 0xd31eu
#define W_WHICH_POKEMON 0xcf92u
#define W_ITEM_QUANTITY 0xcf96u

void port_remove_item_from_inventory_wrapper(struct cpu_register_state *,
	port_u8 *);

static void
cp_a(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 previous = registers->a;

	registers->f = PORT_FLAG_N | (previous == value ? PORT_FLAG_Z : 0)
		| ((previous & 0x0fu) < (value & 0x0fu) ? PORT_FLAG_H : 0)
		| (previous < value ? PORT_FLAG_C : 0);
}

static void
inc_c(struct cpu_register_state *registers)
{
	port_u8 previous = registers->c;

	registers->c++;
	registers->f &= PORT_FLAG_C;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((previous & 0x0fu) == 0x0fu)
		registers->f |= PORT_FLAG_H;
}

/* Port of OaksLabScript_RemoveParcel in scripts/OaksLab.asm. */
__attribute__((noinline, used)) void
port_oaks_lab_script_remove_parcel(struct cpu_register_state *registers,
	port_u8 *memory)
{
	port_u16 pointer = W_BAG_ITEMS;

	registers->h = (port_u8)(W_BAG_ITEMS >> 8);
	registers->l = (port_u8)W_BAG_ITEMS;
	registers->b = 0;
	registers->c = 0;
	for (;;) {
		registers->a = memory[pointer++];
		registers->h = (port_u8)(pointer >> 8);
		registers->l = (port_u8)pointer;
		cp_a(registers, 0xffu);
		if (registers->f & PORT_FLAG_Z)
			return;
		cp_a(registers, OAKS_PARCEL);
		if (registers->f & PORT_FLAG_Z)
			break;
		pointer++;
		registers->h = (port_u8)(pointer >> 8);
		registers->l = (port_u8)pointer;
		inc_c(registers);
	}

	registers->h = (port_u8)(W_NUM_BAG_ITEMS >> 8);
	registers->l = (port_u8)W_NUM_BAG_ITEMS;
	registers->a = registers->c;
	memory[W_WHICH_POKEMON] = registers->a;
	registers->a = 1;
	memory[W_ITEM_QUANTITY] = registers->a;
	port_remove_item_from_inventory_wrapper(registers, memory);
}
