from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "c5f0b8f53e03e0b8ea0020cd044ec178e0b8ea00"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_item_to_inventory_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AddItemToInventory")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY