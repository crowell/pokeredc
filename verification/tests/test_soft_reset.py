from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "cd0e20cde53d0e20cd3937f3afe00fe0ffe043e042e001e002e04be04ae006e007e047e048e0493e80e040cd610031ffdf2100c00100203600230b78"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_soft_reset_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SoftReset")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY