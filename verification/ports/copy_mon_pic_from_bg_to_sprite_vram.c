#include "port_state.h"

/* Port of CopyMonPicFromBGToSpriteVRAM through CopyVideoData. */
__attribute__((noinline, used)) void
port_copy_mon_pic_from_bg_to_sprite_vram(struct cpu_register_state *registers)
{
	registers->d = 0x90;
	registers->e = 0;
	registers->h = 0x80;
	registers->l = 0;
	registers->b = 0;
	registers->c = 0x31;
}
