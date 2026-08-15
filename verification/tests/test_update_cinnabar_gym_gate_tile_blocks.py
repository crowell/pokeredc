from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "0607210a6bc3d635"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_update_cinnabar_gym_gate_tile_blocks_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "UpdateCinnabarGymGateTileBlocks")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY