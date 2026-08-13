from __future__ import annotations

from pathlib import Path
import tomllib

import angr
import pytest

from verification.harness.rom import symbol_location


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
MANIFEST = VERIFY / "ports.toml"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
SYMBOLS = ROOT / "pokered.sym"


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not SYMBOLS.exists(), reason="run `make red`")
def test_port_manifest_references_built_symbols_and_sources() -> None:
    records = tomllib.loads(MANIFEST.read_text())["function"]
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)

    assembly_names: set[str] = set()
    c_names: set[str] = set()
    for record in records:
        assert record["status"] in {"partial", "proven"}
        assert record["assembly_symbol"] not in assembly_names
        assert record["c_symbol"] not in c_names
        assembly_names.add(record["assembly_symbol"])
        c_names.add(record["c_symbol"])

        symbol_location(SYMBOLS, record["assembly_symbol"])
        assert project.loader.find_symbol(record["c_symbol"]) is not None
        assert (ROOT / record["assembly_source"]).is_file()
        assert (ROOT / record["c_source"]).is_file()
        assert record["observables"]
        assert record["proof_domain"]
        assert record["decoder"]
