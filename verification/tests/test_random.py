from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "e5d5c50604218f7acdd635f0d3c1d1e1c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_random_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "Random")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY