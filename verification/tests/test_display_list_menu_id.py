from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "afe0ba3e01e0b7fa5ad0a720043e0118023e0fcdbc352130d7cbf6afea35ccea2ad1fa8bcf6ffa8ccf677eea2ad13e0dea25d1cde830cd292421ccc3110e09fa94cfa72003cd29243e01ea37ccfa2ad1fe0238023e02ea28cc3e04ea24cc3e05ea25cc3e07ea29cc0e0acd3937"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_list_menu_id_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "DisplayListMenuID")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY