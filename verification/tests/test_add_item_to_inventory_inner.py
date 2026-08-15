from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "fa96cff5c5d5e5e516323e1dbd20073ed3bc200216147e92572aa7280f2a47fa91cfb8ca4a4e237efeff20f1e17aa72836347e873d4f060009fa91cf22fa96cf2236ffc36a4efa96cf477e80fe64da684ed663ea96cf7aa728063e6322c3214ee1a7180377e137e1d1c1c178ea96cfc9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_item_to_inventory_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AddItemToInventory_")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY