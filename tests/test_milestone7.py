"""Tests for Milestone 7: AI Layer, Multi-Provider Support, and Caching."""

from pathlib import Path

from typer.testing import CliRunner

from andoguard.ai.cache import AiCacheManager
from andoguard.ai.chunker import chunk_code, estimate_tokens
from andoguard.ai.prompts import (
    build_ask_prompt,
    build_explain_prompt,
    build_triage_prompt,
)
from andoguard.ai.provider import (
    MockAiProvider,
    get_ai_provider,
    list_ai_providers,
)
from andoguard.api import AndoGuard
from andoguard.cli.main import app

runner = CliRunner()


def test_ai_providers_and_doctor() -> None:
    providers = list_ai_providers()
    names = {p["name"] for p in providers}
    assert "gemini" in names
    assert "openai" in names
    assert "anthropic" in names
    assert "ollama" in names
    assert "mock" in names

    mock_p = get_ai_provider("mock")
    assert isinstance(mock_p, MockAiProvider)
    assert mock_p.is_available() is True
    ok, status = mock_p.check_health()
    assert ok is True

    # Test CLI doctor
    res = runner.invoke(app, ["ai", "doctor"])
    assert res.exit_code == 0
    assert "AI Providers Healthcheck" in res.stdout

    res_json = runner.invoke(app, ["ai", "doctor", "--json"])
    assert res_json.exit_code == 0
    assert '"name": "gemini"' in res_json.stdout


def test_code_chunker() -> None:
    short_code = "public class A { void b() {} }"
    chunks = chunk_code(short_code, max_chars=100)
    assert len(chunks) == 1

    long_code = (
        "package com.example.test;\n\n"
        "public class BigTarget {\n"
        "    public void methodOne() {\n"
        "        int x = 1;\n"
        "        int y = 2;\n"
        "    }\n\n"
        "    public void methodTwo() {\n"
        "        String s = \"testing large method boundaries\";\n"
        "    }\n\n"
        "    public void methodThree() {\n"
        "        boolean flag = true;\n"
        "    }\n"
        "}\n"
    )
    # Force small chunk size to trigger boundary splitting
    chunks2 = chunk_code(long_code, max_chars=120, overlap=30)
    assert len(chunks2) >= 2
    assert estimate_tokens(long_code) > 0


def test_ai_cache(tmp_path: Path) -> None:
    from andoguard.config import AndoGuardConfig

    cfg = AndoGuardConfig(work_dir=tmp_path / "andoguard_test")
    cfg.ensure_directories()
    cache = AiCacheManager(cfg)

    hash_key = cache.compute_hash("mock", "model-v1", "What is reverse engineering?")
    assert cache.get(hash_key) is None

    cache.put(hash_key, "mock", "model-v1", "Reverse engineering is the analysis of binaries.")
    assert cache.get(hash_key) == "Reverse engineering is the analysis of binaries."

    # Clear
    cache.clear()
    assert cache.get(hash_key) is None


def test_ai_prompts() -> None:
    sys1, p1 = build_ask_prompt("How does encryption work?", context="Cipher.getInstance()")
    assert "Cipher.getInstance()" in p1
    assert "AndoGuard AI" in sys1

    sys2, p2 = build_explain_prompt("public void decrypt() {}", "com.example.Crypto#decrypt")
    assert "com.example.Crypto#decrypt" in p2

    findings = [
        {"title": "Hardcoded Key", "severity": "HIGH", "masvs_id": "MASVS-CRYPTO-1", "evidence": "AES key"}
    ]
    sys3, p3 = build_triage_prompt(findings, manifest_summary="debuggable=true")
    assert "Hardcoded Key" in p3
    assert "debuggable=true" in p3


def test_api_ai_methods_with_mock(sample_apk_path: Path) -> None:
    with AndoGuard.open(sample_apk_path) as ag:
        # Ask
        ans = ag.ai_ask("Explain overall app structure", provider="mock")
        assert len(ans) > 0

        # Explain
        explanation = ag.ai_explain("com.example.sample.MainActivity", provider="mock")
        assert "Code Explanation" in explanation

        # Triage
        triage = ag.ai_triage(provider="mock")
        assert "Triage" in triage


def test_cli_ai_commands(sample_apk_path: Path, tmp_path: Path) -> None:
    # Open APK session first
    open_res = runner.invoke(app, ["open", str(sample_apk_path)])
    assert open_res.exit_code == 0

    # Ask
    ask_res = runner.invoke(app, ["ai", "ask", "Explain target components", "--provider", "mock"])
    assert ask_res.exit_code == 0
    assert "AI Response" in ask_res.stdout

    # Explain
    exp_res = runner.invoke(app, ["ai", "explain", "com.example.sample.MainActivity", "--provider", "mock"])
    assert exp_res.exit_code == 0
    assert "Code Explanation" in exp_res.stdout

    # Triage
    tri_res = runner.invoke(app, ["ai", "triage", "--provider", "mock"])
    assert tri_res.exit_code == 0
    assert "Triage" in tri_res.stdout

    # Triage out to file
    out_file = tmp_path / "triage.md"
    tri_out = runner.invoke(app, ["ai", "triage", "--provider", "mock", "--out", str(out_file)])
    assert tri_out.exit_code == 0
    assert out_file.exists()
    assert "Triage" in out_file.read_text(encoding="utf-8")
