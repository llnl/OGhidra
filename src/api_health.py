"""Shared generation probe for OpenAI-compatible Custom API endpoints."""

import re

import requests


def build_health_request(url: str, api_key: str, model: str, verify_ssl: bool) -> dict:
    """Build an isolated probe; never change normal generation settings."""
    url = url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/chat/completions" if url.endswith("/v1") else "/v1/chat/completions"
    return {
        "url": url,
        "headers": {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        "json": {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with OK."}],
            "max_completion_tokens": 4096,
        },
        "timeout": (10, 60),
        "verify": verify_ssl,
    }


def health_error_detail(response) -> str:
    """Preserve provider errors, including non-JSON gateway responses."""
    try:
        return str(response.json())
    except ValueError:
        return response.text


def post_health_request(request: dict):
    """Retry once with the legacy token field only when it is explicitly rejected.

    Network errors and unrelated API errors are left to the caller. Never drop
    the output budget or retry arbitrary parameter changes.
    """
    kwargs = {**request, "json": dict(request["json"])}
    response = requests.post(**kwargs)
    if response.status_code not in (400, 422):
        return response

    detail = health_error_detail(response).lower()
    field = "max_completion_tokens"
    # Match an actual rejection, not a token-exhaustion error mentioning limits.
    rejected = re.search(
        rf"(?:unsupported|unrecognized|unknown) (?:parameter|argument|field)[: ]*['\"]?{field}\b"
        rf"|\b{field}\b['\"]? (?:is |are )?(?:not supported|unsupported|not allowed)",
        detail,
    )
    if rejected:
        kwargs["json"] = dict(kwargs["json"])
        kwargs["json"]["max_tokens"] = kwargs["json"].pop(field)
        response = requests.post(**kwargs)
    return response
