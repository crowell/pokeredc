#include "port_state.h"

#define UPDATE_SPRITES_ENABLED 0xcfcbU
#define OAM_BASE 0xc300U
#define PLAYER_Y 0xc104U
#define PLAYER_IMAGE 0xc102U
#define SAVED_Y 0xcd4fU
#define SAVED_FACING 0xcd50U
#define HIDDEN_Y 160U

void port_delay_frames(struct delay_frame_state *, const port_u8 *);
void port_gb_fade_out_to_white(struct cpu_register_state *, port_u8 *);
void port_restore_facing_direction_and_y_screen_pos(struct restore_facing_state *);

/* Complete LeaveMapThroughHoleAnim, including the facing/position tail call. */
__attribute__((noinline, used)) void
port_leave_map_through_hole_anim(struct cpu_register_state *r, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;
	struct restore_facing_state restore;

	r->a = 0xff;
	memory[UPDATE_SPRITES_ENABLED] = r->a;
	r->a = memory[OAM_BASE + 2];
	memory[OAM_BASE + 10] = r->a;
	r->a = memory[OAM_BASE + 6];
	memory[OAM_BASE + 14] = r->a;
	r->a = HIDDEN_Y;
	memory[OAM_BASE] = r->a;
	memory[OAM_BASE + 4] = r->a;
	r->c = 2;
	delay.registers = *r;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*r = delay.registers;

	r->a = HIDDEN_Y;
	memory[OAM_BASE + 8] = r->a;
	memory[OAM_BASE + 12] = r->a;
	port_gb_fade_out_to_white(r, memory);
	r->a = 1;
	memory[UPDATE_SPRITES_ENABLED] = r->a;

	restore.registers = *r;
	restore.saved_screen_y = memory[SAVED_Y];
	restore.saved_facing_direction = memory[SAVED_FACING];
	restore.sprite_y_pixels = memory[PLAYER_Y];
	restore.sprite_image_index = memory[PLAYER_IMAGE];
	port_restore_facing_direction_and_y_screen_pos(&restore);
	*r = restore.registers;
	memory[PLAYER_Y] = restore.sprite_y_pixels;
	memory[PLAYER_IMAGE] = restore.sprite_image_index;
}
