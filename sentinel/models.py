"""Meta Model API client built on the OpenAI SDK."""

import os
import time

try:
    from dotenv import load_dotenv
except ImportError:  # optional: only loads .env files for local runs
    def load_dotenv(*args, **kwargs):
        return False

try:
    from openai import OpenAI, RateLimitError
except ImportError:  # optional until chat() is actually called
    OpenAI = None

    class RateLimitError(Exception):
        pass

load_dotenv()

BASE_URL = "https://api.meta.ai/v1"


def _client():
    if OpenAI is None:
        raise RuntimeError(
            "The 'openai' package is not installed. "
            "Install it with: pip install -r requirements.txt")
    return OpenAI(base_url=BASE_URL, api_key=os.getenv("META_API_KEY"))


def chat(model, messages, json_mode=False, max_retries=3, backoff_seconds=1.0):
    """Send a chat request to the Meta Model API.

    Retries on 429 (rate limit) with exponential backoff.
    """
    kwargs = {}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            response = _client().chat.completions.create(
                model=model, messages=messages, **kwargs
            )
            return response.choices[0].message.content
        except RateLimitError as exc:
            last_error = exc
            if attempt < max_retries:
                time.sleep(backoff_seconds * (2 ** attempt))
    raise last_error
