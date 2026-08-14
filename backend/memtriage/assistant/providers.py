"""Where a chat request may be sent, and how.

Two transports cover every provider here: Anthropic's Messages API, and the
OpenAI-compatible Chat Completions shape that the rest of them expose. The
registry is also the egress allowlist — a request can only reach a base URL
listed here, so a provider name arriving from the browser cannot be turned into
a request against an internal address.

A custom base URL is available for self-hosted gateways but is refused unless
MEMTRIAGE_ALLOW_CUSTOM_LLM_BASE_URL is set, and it must still be https or a
loopback address.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

ANTHROPIC = "anthropic"
OPENAI_COMPATIBLE = "openai"


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    transport: str
    base_url: str
    default_model: str
    models: tuple[str, ...]
    key_env: str
    docs_url: str
    prompt_cache: str  # explicit | automatic | none
    needs_key: bool = True
    note: str = ""
    extra_headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["models"] = list(self.models)
        return data


REGISTRY: tuple[Provider, ...] = (
    Provider(
        id=ANTHROPIC,
        label="Anthropic",
        transport=ANTHROPIC,
        base_url="https://api.anthropic.com",
        default_model="claude-opus-5",
        models=("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"),
        key_env="ANTHROPIC_API_KEY",
        docs_url="https://docs.claude.com/en/api/overview",
        prompt_cache="explicit",
        note=("The briefing is sent as a cached system block, so repeat questions "
              "re-read it from cache rather than re-sending it."),
    ),
    Provider(
        id="openai",
        label="OpenAI",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.openai.com/v1",
        default_model="gpt-4.1",
        models=("gpt-4.1", "gpt-4.1-mini", "o4-mini"),
        key_env="OPENAI_API_KEY",
        docs_url="https://platform.openai.com/docs/api-reference/chat",
        prompt_cache="automatic",
    ),
    Provider(
        id="groq",
        label="Groq",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        models=("llama-3.3-70b-versatile", "llama-3.1-8b-instant",
                "deepseek-r1-distill-llama-70b"),
        key_env="GROQ_API_KEY",
        docs_url="https://console.groq.com/docs/api-reference",
        prompt_cache="none",
    ),
    Provider(
        id="openrouter",
        label="OpenRouter",
        transport=OPENAI_COMPATIBLE,
        base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-opus-5",
        models=("anthropic/claude-opus-5", "openai/gpt-4.1", "google/gemini-2.5-pro"),
        key_env="OPENROUTER_API_KEY",
        docs_url="https://openrouter.ai/docs",
        prompt_cache="automatic",
        note="Routes to many upstream models behind one key.",
    ),
    Provider(
        id="together",
        label="Together AI",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        models=("meta-llama/Llama-3.3-70B-Instruct-Turbo",
                "Qwen/Qwen2.5-72B-Instruct-Turbo"),
        key_env="TOGETHER_API_KEY",
        docs_url="https://docs.together.ai/reference/chat-completions",
        prompt_cache="none",
    ),
    Provider(
        id="mistral",
        label="Mistral",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.mistral.ai/v1",
        default_model="mistral-large-latest",
        models=("mistral-large-latest", "mistral-small-latest"),
        key_env="MISTRAL_API_KEY",
        docs_url="https://docs.mistral.ai/api/",
        prompt_cache="none",
    ),
    Provider(
        id="xai",
        label="xAI",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.x.ai/v1",
        default_model="grok-4",
        models=("grok-4", "grok-3-mini"),
        key_env="XAI_API_KEY",
        docs_url="https://docs.x.ai/api",
        prompt_cache="none",
    ),
    Provider(
        id="deepseek",
        label="DeepSeek",
        transport=OPENAI_COMPATIBLE,
        base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat",
        models=("deepseek-chat", "deepseek-reasoner"),
        key_env="DEEPSEEK_API_KEY",
        docs_url="https://api-docs.deepseek.com/",
        prompt_cache="automatic",
    ),
    Provider(
        id="google",
        label="Google Gemini",
        transport=OPENAI_COMPATIBLE,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-2.5-pro",
        models=("gemini-2.5-pro", "gemini-2.5-flash"),
        key_env="GEMINI_API_KEY",
        docs_url="https://ai.google.dev/gemini-api/docs/openai",
        prompt_cache="automatic",
        note="Uses Gemini's OpenAI-compatible endpoint.",
    ),
    Provider(
        id="ollama",
        label="Ollama (local)",
        transport=OPENAI_COMPATIBLE,
        base_url="http://localhost:11434/v1",
        default_model="llama3.1",
        models=("llama3.1", "qwen2.5", "mistral"),
        key_env="",
        docs_url="https://docs.ollama.com/openai",
        prompt_cache="none",
        needs_key=False,
        note=("Runs on the analyst's own machine, so the briefing never leaves the "
              "host. The API container must be able to reach it."),
    ),
    Provider(
        id="lmstudio",
        label="LM Studio (local)",
        transport=OPENAI_COMPATIBLE,
        base_url="http://localhost:1234/v1",
        default_model="local-model",
        models=("local-model",),
        key_env="",
        docs_url="https://lmstudio.ai/docs/app/api/endpoints/openai",
        prompt_cache="none",
        needs_key=False,
        note="Local server; the briefing never leaves the host.",
    ),
    Provider(
        id="custom",
        label="Custom OpenAI-compatible endpoint",
        transport=OPENAI_COMPATIBLE,
        base_url="",
        default_model="",
        models=(),
        key_env="",
        docs_url="",
        prompt_cache="none",
        needs_key=False,
        note=("Disabled unless MEMTRIAGE_ALLOW_CUSTOM_LLM_BASE_URL is set. Only "
              "https, or a loopback address, is accepted."),
    ),
)

BY_ID = {p.id: p for p in REGISTRY}


class ProviderError(ValueError):
    """A provider or base URL that will not be used."""


def get_provider(provider_id: str) -> Provider:
    provider = BY_ID.get((provider_id or "").strip().lower())
    if provider is None:
        raise ProviderError(
            f"Unknown provider '{provider_id}'. Known providers: "
            f"{', '.join(sorted(BY_ID))}."
        )
    return provider


def custom_base_url_allowed() -> bool:
    return os.environ.get("MEMTRIAGE_ALLOW_CUSTOM_LLM_BASE_URL", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def resolve_base_url(provider: Provider, override: str | None) -> str:
    """The URL a request may actually be sent to."""
    if provider.id == "custom":
        if not custom_base_url_allowed():
            raise ProviderError(
                "Custom endpoints are disabled. Set MEMTRIAGE_ALLOW_CUSTOM_LLM_BASE_URL=1 "
                "to enable one, or pick a provider from the list."
            )
        if not override:
            raise ProviderError("A custom provider needs a base URL.")
        return _validate_custom(override)
    if override and override.rstrip("/") != provider.base_url.rstrip("/"):
        raise ProviderError(
            f"{provider.label} requests go to {provider.base_url}; a different base URL "
            "is only allowed with the custom provider."
        )
    return provider.base_url


def _validate_custom(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ProviderError("A custom base URL must be http or https.")
    host = parsed.hostname or ""
    if not host:
        raise ProviderError("A custom base URL must include a host.")
    if parsed.scheme == "http" and not _is_loopback(host):
        raise ProviderError("Plain http is only accepted for a loopback address.")
    return url.rstrip("/")


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "host.docker.internal"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def catalogue() -> list[dict]:
    """What the UI offers, with the custom entry's availability resolved."""
    allow_custom = custom_base_url_allowed()
    rows = []
    for provider in REGISTRY:
        if provider.id == "custom" and not allow_custom:
            continue
        row = provider.to_dict()
        row["local"] = not provider.needs_key and provider.id != "custom"
        rows.append(row)
    return rows
