"""OpenAI-compatible Chat Completions transport.

Every non-Anthropic provider in the registry speaks this shape, so one transport
covers OpenAI, Groq, OpenRouter, Together, Mistral, xAI, DeepSeek, Gemini's
compatibility endpoint, and a local Ollama or LM Studio server. The briefing goes
first in the message list, which is where providers with automatic prefix caching
look for a reusable prefix.
"""
from __future__ import annotations

from .errors import AssistantError, classify_exception

DEFAULT_MAX_TOKENS = 8000


def available() -> bool:
    try:
        import openai  # noqa: F401
        return True
    except Exception:
        return False


def chat(*, api_key: str, model: str, system: str, messages: list[dict],
         base_url: str, timeout_s: float, max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
    try:
        import openai
    except Exception as exc:
        raise AssistantError(
            "The OpenAI SDK is not installed in this environment. `pip install openai`.",
            code="sdk_missing",
        ) from exc

    client = openai.OpenAI(
        api_key=api_key or "not-required",
        base_url=base_url,
        timeout=timeout_s,
        max_retries=1,
    )
    try:
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "system", "content": system}, *messages],
        )
    except Exception as exc:
        raise classify_exception(exc, api_key) from None

    choice = response.choices[0] if response.choices else None
    usage = getattr(response, "usage", None)
    cached = 0
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        cached = getattr(details, "cached_tokens", 0) or 0
    return {
        "text": ((choice.message.content or "") if choice else "").strip(),
        "model": getattr(response, "model", model),
        "stop_reason": getattr(choice, "finish_reason", None) if choice else None,
        "usage": {
            "input_tokens": getattr(usage, "prompt_tokens", None),
            "output_tokens": getattr(usage, "completion_tokens", None),
            "cache_read_input_tokens": cached or None,
            "cache_creation_input_tokens": None,
        },
    }
