#include "port_state.h"

void port_get_tile_id_list(struct cpu_register_state *);
void port_get_mon_sprite_tilemap_pointer_from_row_count(
	struct subanimation_transform_state *);
void port_copy_pic_tiles(struct copy_tile_ids_state *, port_u8 memory[65536]);
void port_delay3(struct cpu_register_state *, port_u8 *);

/* Port of AnimationShowMonPic in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_animation_show_mon_pic(struct animation_show_mon_pic_state *state)
{
	struct subanimation_transform_state pointer;
	struct copy_tile_ids_state copy;

	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	port_get_tile_id_list(&state->registers);

	pointer.registers = state->registers;
	pointer.whose_turn = state->whose_turn;
	port_get_mon_sprite_tilemap_pointer_from_row_count(&pointer);
	state->registers = pointer.registers;

	copy.registers = state->registers;
	copy.base_tile = state->base_tile;
	copy.auto_transfer = state->auto_transfer;
	copy.whose_turn = state->whose_turn;
	port_copy_pic_tiles(&copy, state->memory);
	state->registers = copy.registers;
	state->base_tile = copy.base_tile;
	state->auto_transfer = copy.auto_transfer;

	port_delay3(&state->registers, state->memory);
}
