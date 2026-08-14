"""Anthropic Messages API transport.

The briefing goes in as a `system` block marked `cache_control: ephemeral`, which
is what makes a multi-turn conversation cheap: the prefix is read from cache on
every turn after the first, and `usage.cache_read_input_tokens` reports whether
that actually happened.
"""
from __future__ import annotations

from .errors import AssistantError, classify_exception

DEFAULT_MAX_TOKENS = 8000


def available() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:
        return False


def chat(*, api_key: str, model: str, system: str, messages: list[dict],
         base_url: str, timeout_s: float, max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
    try:
        import anthropic
    except Exception as exc:
        raise AssistantError(
            "The Anthropic SDK is not installed in this environment. "
            "`pip install anthropic`, or choose an OpenAI-compatible provider.",
            code="sdk_missing",
        ) from exc

    client = anthropic.Anthropic(api_key=api_key, base_url=base_url, timeout=timeout_s,
                                 max_retries=1)
    try:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=[{
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=messages,
        )
    except Exception as exc:
        raise classify_exception(exc, api_key) from None

    text = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )
    usage = getattr(response, "usage", None)
    return {
        "text": text.strip(),
        "model": getattr(response, "model", model),
        "stop_reason": getattr(response, "stop_reason", None),
        "usage": {
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", None),
        },
    }
