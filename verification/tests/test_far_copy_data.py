from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "eae9cef0b8f5fae9cee0b8ea0020cdb500f1e0b8"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_far_copy_data_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "FarCopyData")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY