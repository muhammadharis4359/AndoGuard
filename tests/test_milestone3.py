"""Comprehensive tests for Milestone 3: Classes, Methods, Disassembly, Decompilation, and CFG."""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from andoguard.adapters.fallback import FallbackAdapter
from andoguard.api import AndoGuard
from andoguard.cli.main import app
from andoguard.models import ControlFlowGraph
from andoguard.static.cfg import build_cfg_from_basic_blocks

runner = CliRunner()


class MockInstruction:
    def __init__(self, name: str, output: str) -> None:
        self._name = name
        self._output = output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


class MockBasicBlock:
    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        instructions: list[MockInstruction],
        children: list[Any],
    ) -> None:
        self.name = name
        self.start = start
        self.end = end
        self._instructions = instructions
        self.childs = children

    def get_instructions(self) -> list[MockInstruction]:
        return self._instructions


def test_cfg_generation_from_basic_blocks() -> None:
    """Test CFG builder properly constructs BasicBlockInfo and DOT graph."""
    bb3 = MockBasicBlock("BB3", 0x20, 0x30, [MockInstruction("return-void", "")], [])
    bb2 = MockBasicBlock(
        "BB2", 0x10, 0x20, [MockInstruction("const/4", "v0, 1")], [(0x20, "goto", bb3)]
    )
    bb1 = MockBasicBlock(
        "BB1",
        0x0,
        0x10,
        [MockInstruction("if-eqz", "v0, +8")],
        [(0x10, "fallthrough", bb2), (0x20, "branch", bb3)],
    )

    cfg = build_cfg_from_basic_blocks("testMethod", [bb1, bb2, bb3])

    assert isinstance(cfg, ControlFlowGraph)
    assert cfg.method == "testMethod"
    assert len(cfg.blocks) == 3
    assert cfg.blocks[0].name == "BB1"
    assert cfg.blocks[0].start == 0x0
    assert cfg.blocks[0].end == 0x10
    assert "BB2" in cfg.blocks[0].children
    assert "BB3" in cfg.blocks[0].children
    assert 'digraph "CFG for testMethod"' in cfg.dot
    assert '"BB1" -> "BB2";' in cfg.dot
    assert '"BB1" -> "BB3";' in cfg.dot
    assert '"BB2" -> "BB3";' in cfg.dot


def test_fallback_adapter_m3_methods(sample_apk_path: Path) -> None:
    """Ensure FallbackAdapter safely handles M3 inspection methods."""
    adapter = FallbackAdapter(sample_apk_path)
    adapter.open(sample_apk_path)

    assert adapter.get_classes() == []
    assert adapter.get_methods("Lcom/example/Test;") == []
    assert adapter.get_class_detail("Lcom/example/Test;") is None
    assert adapter.get_fields("Lcom/example/Test;") == []

    disasm = adapter.disassemble_method("Lcom/example/Test;", "testMethod")
    assert "Disassembly unavailable" in disasm.instructions[0]

    code = adapter.decompile_source("Lcom/example/Test;", "testMethod")
    assert "Decompilation unavailable" in code.source
    adapter.close()


def test_api_classes_and_methods(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test classes and methods queries through public AndoGuard API."""
    with AndoGuard.open(
        sample_apk_path, session_name="m3-classes-test", work_dir=tmp_path
    ) as ag:
        classes = ag.classes()
        assert isinstance(classes, list)

        filtered = ag.classes(grep="Main", pkg="com.example")
        assert isinstance(filtered, list)

        methods = ag.methods("Lcom/example/NonExistent;")
        assert isinstance(methods, list)

        detail = ag.class_detail("Lcom/example/NonExistent;")
        assert detail is None

        fields = ag.fields("Lcom/example/NonExistent;")
        assert isinstance(fields, list)


def test_api_disassemble_and_code(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test Dalvik disassembly and decompilation through AndoGuard API."""
    with AndoGuard.open(
        sample_apk_path, session_name="m3-disasm-test", work_dir=tmp_path
    ) as ag:
        # Disassembly with and without CFG
        disasm = ag.disassemble_method(
            "Lcom/example/MainActivity;", "onCreate", cfg=True
        )
        assert disasm.target == "Lcom/example/MainActivity;#onCreate"
        assert len(disasm.instructions) > 0

        # Decompile to Java
        java_code = ag.decompile_source(
            "Lcom/example/MainActivity;", "onCreate", lang="java", cfg=True
        )
        assert java_code.language == "java"
        assert java_code.target == "Lcom/example/MainActivity;#onCreate"
        assert len(java_code.source) > 0

        # Decompile to Dalvik
        dalvik_code = ag.decompile_source(
            "Lcom/example/MainActivity;", "onCreate", lang="dalvik"
        )
        assert dalvik_code.language == "dalvik"
        assert len(dalvik_code.source) > 0


def test_cli_classes_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard classes' command."""
    open_res = runner.invoke(
        app,
        ["open", str(sample_apk_path), "--work-dir", str(tmp_path)],
    )
    assert open_res.exit_code == 0

    # Normal classes listing
    res = runner.invoke(
        app,
        ["classes", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    # JSON classes listing
    json_res = runner.invoke(
        app,
        ["classes", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert isinstance(parsed, list)


def test_cli_methods_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard methods' command."""
    runner.invoke(
        app,
        ["open", str(sample_apk_path), "--work-dir", str(tmp_path)],
    )

    res = runner.invoke(
        app,
        ["methods", "Lcom/example/MainActivity;", "--work-dir", str(tmp_path)],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        ["methods", "Lcom/example/MainActivity;", "--json", "--work-dir", str(tmp_path)],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert "class" in parsed
    assert "methods" in parsed


def test_cli_disasm_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard disasm' command with and without CFG."""
    runner.invoke(
        app,
        ["open", str(sample_apk_path), "--work-dir", str(tmp_path)],
    )

    res = runner.invoke(
        app,
        [
            "disasm",
            "com.example.MainActivity#onCreate",
            "--cfg",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert res.exit_code == 0

    json_res = runner.invoke(
        app,
        [
            "disasm",
            "com.example.MainActivity#onCreate",
            "--json",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert "target" in parsed
    assert "instructions" in parsed


def test_cli_code_command(sample_apk_path: Path, tmp_path: Path) -> None:
    """Test CLI 'andoguard code' command for Java and Dalvik languages."""
    runner.invoke(
        app,
        ["open", str(sample_apk_path), "--work-dir", str(tmp_path)],
    )

    # Java output
    res = runner.invoke(
        app,
        [
            "code",
            "com.example.MainActivity#onCreate",
            "--lang",
            "java",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert res.exit_code == 0

    # Dalvik output
    dalvik_res = runner.invoke(
        app,
        [
            "code",
            "com.example.MainActivity#onCreate",
            "--lang",
            "dalvik",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert dalvik_res.exit_code == 0

    # JSON output
    json_res = runner.invoke(
        app,
        [
            "code",
            "com.example.MainActivity#onCreate",
            "--json",
            "--work-dir",
            str(tmp_path),
        ],
    )
    assert json_res.exit_code == 0
    parsed = json.loads(json_res.output)
    assert parsed["language"] == "java"
    assert "source" in parsed
