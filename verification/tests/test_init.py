from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f3afe00fe0ffe043e042e001e002e04be04ae006e007e047e048e0493e80e040cd610031ffdf2100c00100203600230b78b120f8cd04202180ff017f00cde036cd82003e01e0b8ea0020cded4bafe0d7e041e0aee0afe00f3e0de0ff3e90e0b0e04a3e07e04b3effe0aa2698cdf01c269ccdf01c3ee3e0403e10e08acd0e20fb3e40cd6d3e3e1feaefc0eaf0c03e9ce0bdafe0bc3deacbcf3e32cd6d3ecd6100cd0420cddc3dcd82003ee3e040c3b742"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "Init")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY