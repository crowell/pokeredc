#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
rom_load(struct mac_rom *rom, const char *path)
{
	FILE *f;

	rom->data = NULL;
	rom->size = 0;

	f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "pokered-mac: cannot open ROM '%s'\n", path);
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	rom->size = (size_t)ftell(f);
	rewind(f);
	if (rom->size < 0x8000 || rom->size % 0x4000 != 0) {
		fprintf(stderr,
		    "pokered-mac: '%s' is not a bank-aligned GB ROM\n", path);
		fclose(f);
		return -1;
	}
	rom->data = malloc(rom->size);
	if (rom->data == NULL) {
		fclose(f);
		return -1;
	}
	if (fread(rom->data, 1, rom->size, f) != rom->size) {
		fprintf(stderr, "pokered-mac: short read on '%s'\n", path);
		free(rom->data);
		rom->data = NULL;
		rom->size = 0;
		fclose(f);
		return -1;
	}
	fclose(f);

	printf("pokered-mac: loaded %s (%zu banks)\n", path,
	    rom->size / 0x4000);
	return 0;
}

void
rom_unload(struct mac_rom *rom)
{
	free(rom->data);
	rom->data = NULL;
	rom->size = 0;
}

void
rom_map_bank(uint8_t *memory, const struct mac_rom *rom, unsigned bank)
{
	size_t offset;

	if (rom == NULL || rom->data == NULL)
		return;
	offset = (size_t)bank * ROM_WINDOW_SIZE;
	if (bank == 0 || offset + ROM_WINDOW_SIZE > rom->size)
		return; /* unmapped: hardware reads open-bus garbage; keep old */
	memcpy(memory + ROM_WINDOW_START, rom->data + offset, ROM_WINDOW_SIZE);
}

void
gb_reset_memory(uint8_t *memory, const struct mac_rom *rom)
{
	memset(memory, 0, GB_STORAGE_SIZE);
	if (rom != NULL && rom->data != NULL && rom->size >= ROM_WINDOW_SIZE) {
		memcpy(memory + ROM_BANK0_START, rom->data, ROM_WINDOW_SIZE);
		for (unsigned bank = 0;
		    bank < PORT_ROM_BANK_COUNT &&
		    (size_t)(bank + 1u) * ROM_WINDOW_SIZE <= rom->size;
		    bank++) {
			memcpy(memory + PORT_ROM_BACKING_BASE +
			    (size_t)bank * PORT_ROM_WINDOW_SIZE,
			    rom->data + (size_t)bank * ROM_WINDOW_SIZE,
			    ROM_WINDOW_SIZE);
		}
	}
	/* Init leaves the title-screen bank mapped; ports read the window. */
	rom_map_bank(memory, rom, 1);
	memory[H_LOADED_ROM_BANK] = 1;
	memory[R_ROMB] = 1;
	port_sync_rom_window(memory, 1);
}

void
rom_sync_window(uint8_t *memory, const struct mac_rom *rom,
	unsigned *cached_bank)
{
	unsigned bank = memory[H_LOADED_ROM_BANK];

	/* Ports may synchronize the window internally without updating the
	 * platform cache. Always remap here so the next VBlank cannot reuse a
	 * stale host-side window. */
	rom_map_bank(memory, rom, bank);
	*cached_bank = bank;
}
