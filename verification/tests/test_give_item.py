from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "78ea1ed1ea91cf79ea96cf211dd3cdcf2bd0cdcf2fcd263837c978ea91cf79ea27d1afea49cc061321a57dc3d635e5d5c50604218f7acdd635f0d3c1d1e1c9ea4ecc"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_give_item_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GiveItem")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY