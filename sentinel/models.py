"""Meta Model API client built on the OpenAI SDK."""

import os
import time

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

load_dotenv()

BASE_URL = "https://api.meta.ai/v1"


def _client() -> OpenAI:
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
