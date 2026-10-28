"""Multi-provider AI reasoning engine: Gemini, OpenAI, Anthropic, Ollama, and Mock."""

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from andoguard.config import AndoGuardConfig
from andoguard.errors import (
    AiAuthenticationError,
    AiProviderUnavailableError,
    AiRateLimitError,
)


class AiProvider(ABC):
    """Abstract protocol for AI model reasoning providers."""

    def __init__(self, model: str) -> None:
        self.model = model

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if required API credentials or local service are configured."""

    @abstractmethod
    def check_health(self) -> tuple[bool, str]:
        """Perform a quick health/connectivity check."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        """Execute text generation request."""


class GeminiProvider(AiProvider):
    """Google Gemini AI provider using official REST API."""

    def __init__(self, model: str = "gemini-1.5-flash") -> None:
        super().__init__(model)
        self.api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    @property
    def name(self) -> str:
        return "gemini"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def check_health(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "Missing GEMINI_API_KEY or GOOGLE_API_KEY environment variable"
        return True, f"Configured (model: {self.model})"

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise AiProviderUnavailableError("gemini", "API key not found in environment.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload: dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                candidates = resp_json.get("candidates", [])
                if not candidates:
                    return ""
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                return "".join(p.get("text", "") for p in parts)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AiAuthenticationError("gemini") from e
            if e.code == 429:
                raise AiRateLimitError("gemini") from e
            raise AiProviderUnavailableError("gemini", f"HTTP {e.code}: {e.reason}") from e
        except Exception as e:
            raise AiProviderUnavailableError("gemini", str(e)) from e


class OpenAiCompatibleProvider(AiProvider):
    """OpenAI and OpenAI-compatible API provider (e.g. LocalAI, vLLM, Groq)."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        super().__init__(model)
        self.base_url = base_url.rstrip("/")
        self.api_key = os.environ.get("OPENAI_API_KEY")

    @property
    def name(self) -> str:
        return "openai"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def check_health(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "Missing OPENAI_API_KEY environment variable"
        return True, f"Configured ({self.base_url}, model: {self.model})"

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise AiProviderUnavailableError("openai", "OPENAI_API_KEY not found.")

        url = f"{self.base_url}/chat/completions"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                choices = resp_json.get("choices", [])
                if not choices:
                    return ""
                return str(choices[0].get("message", {}).get("content", ""))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AiAuthenticationError("openai") from e
            if e.code == 429:
                raise AiRateLimitError("openai") from e
            raise AiProviderUnavailableError("openai", f"HTTP {e.code}: {e.reason}") from e
        except Exception as e:
            raise AiProviderUnavailableError("openai", str(e)) from e


class AnthropicProvider(AiProvider):
    """Anthropic Claude API provider."""

    def __init__(self, model: str = "claude-3-5-sonnet-20241022") -> None:
        super().__init__(model)
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")

    @property
    def name(self) -> str:
        return "anthropic"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def check_health(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "Missing ANTHROPIC_API_KEY environment variable"
        return True, f"Configured (model: {self.model})"

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        if not self.api_key:
            raise AiProviderUnavailableError("anthropic", "ANTHROPIC_API_KEY not found.")

        url = "https://api.anthropic.com/v1/messages"
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                contents = resp_json.get("content", [])
                text_parts = [c.get("text", "") for c in contents if c.get("type") == "text"]
                return "".join(text_parts)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AiAuthenticationError("anthropic") from e
            if e.code == 429:
                raise AiRateLimitError("anthropic") from e
            raise AiProviderUnavailableError("anthropic", f"HTTP {e.code}: {e.reason}") from e
        except Exception as e:
            raise AiProviderUnavailableError("anthropic", str(e)) from e


class OllamaProvider(AiProvider):
    """Local LLM inference via Ollama."""

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
    ) -> None:
        super().__init__(model)
        self.base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    def is_available(self) -> bool:
        # Check if local endpoint responds
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                status = getattr(resp, "status", None)
                return bool(status == 200)
        except Exception:
            return False

    def check_health(self) -> tuple[bool, str]:
        if self.is_available():
            return True, f"Online ({self.base_url}, model: {self.model})"
        return False, f"Ollama service unreachable at {self.base_url}"

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        url = f"{self.base_url}/api/chat"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                return str(resp_json.get("message", {}).get("content", ""))
        except Exception as e:
            raise AiProviderUnavailableError("ollama", str(e)) from e


class MockAiProvider(AiProvider):
    """Deterministic simulation provider for testing and offline environments."""

    def __init__(
        self,
        model: str = "mock-reasoning-v1",
        default_response: str | None = None,
    ) -> None:
        super().__init__(model)
        self.default_response = default_response or (
            "AndoGuard Mock AI Analysis:\n"
            "- Target architecture analyzed.\n"
            "- Findings verified against OWASP MASVS.\n"
            "- No immediate critical exploit path identified in simulated mode."
        )
        self.call_history: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "mock"

    def is_available(self) -> bool:
        return True

    def check_health(self) -> tuple[bool, str]:
        return True, "Mock provider ready (Simulation mode)"

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        self.call_history.append({"prompt": prompt, "system": system})
        if "action json" in prompt.lower() or "available tools" in (system or "").lower():
            if "step: 1" in prompt.lower() or "step 1" in prompt.lower():
                return (
                    '{\n'
                    '  "thought": "Inspect manifest for exported components and permissions",\n'
                    '  "tool": "get_manifest_info",\n'
                    '  "args": {},\n'
                    '  "finished": false\n'
                    '}'
                )
            return (
                '{\n'
                '  "thought": "Goal achieved after inspection",\n'
                '  "tool": "finish",\n'
                '  "args": {},\n'
                '  "finished": true\n'
                '}'
            )
        if "triage" in prompt.lower() or "findings" in prompt.lower():
            return (
                "### AndoGuard AI Security Triage\n\n"
                "1. **Risk Posture**: Medium risk detected.\n"
                "2. **Critical Findings**: Exported components and cleartext traffic identified.\n"
                "3. **Remediation**: Set android:exported=false and require HTTPS."
            )
        if "explain" in prompt.lower() or "decompiled" in prompt.lower():
            return (
                "### Code Explanation\n\n"
                "1. **Purpose**: Handles authentication and credential validation.\n"
                "2. **Logic**: Checks input string against internal hash.\n"
                "3. **Security Assessment**: Insecure hardcoded credential pattern detected."
            )
        return self.default_response


def get_ai_provider(
    provider_name: str | None = None,
    config: AndoGuardConfig | None = None,
) -> AiProvider:
    """Instantiate requested or default configured AI provider."""
    cfg = config or AndoGuardConfig.load()
    name = (provider_name or cfg.default_ai_provider).lower().strip()

    if name == "gemini":
        return GeminiProvider(model=cfg.gemini_model)
    elif name == "openai":
        return OpenAiCompatibleProvider(model=cfg.openai_model, base_url=cfg.openai_base_url)
    elif name == "anthropic":
        return AnthropicProvider(model=cfg.anthropic_model)
    elif name == "ollama":
        return OllamaProvider(model=cfg.ollama_model, base_url=cfg.ollama_base_url)
    elif name == "mock":
        return MockAiProvider()
    else:
        raise AiProviderUnavailableError(name, f"Unknown AI provider '{name}'.")


def list_ai_providers(config: AndoGuardConfig | None = None) -> list[dict[str, Any]]:
    """Inspect and report health status of all available providers."""
    cfg = config or AndoGuardConfig.load()
    providers: list[AiProvider] = [
        GeminiProvider(model=cfg.gemini_model),
        OpenAiCompatibleProvider(model=cfg.openai_model, base_url=cfg.openai_base_url),
        AnthropicProvider(model=cfg.anthropic_model),
        OllamaProvider(model=cfg.ollama_model, base_url=cfg.ollama_base_url),
        MockAiProvider(),
    ]

    results: list[dict[str, Any]] = []
    for p in providers:
        avail, status = p.check_health()
        results.append(
            {
                "name": p.name,
                "model": p.model,
                "available": avail,
                "status": status,
                "is_default": p.name == cfg.default_ai_provider.lower().strip(),
            }
        )
    return results
