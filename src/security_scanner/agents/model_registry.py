"""
AI model registry with cost tracking.

Provides a thin wrapper for calling LLM APIs (Anthropic, OpenAI) using
only stdlib (urllib.request + json).  No external SDK required.
"""

import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ModelProvider:
    """Describes an AI model with pricing info."""

    name: str
    model: str
    api_url: str
    api_key_env: str
    input_cost_per_1k: float   # USD per 1K input tokens
    output_cost_per_1k: float  # USD per 1K output tokens


# Known providers
PROVIDERS: Dict[str, ModelProvider] = {
    "anthropic": ModelProvider(
        name="anthropic",
        model="claude-sonnet-4-20250514",
        api_url="https://api.anthropic.com/v1/messages",
        api_key_env="ANTHROPIC_API_KEY",
        input_cost_per_1k=0.003,
        output_cost_per_1k=0.015,
    ),
    "openai": ModelProvider(
        name="openai",
        model="gpt-4o-mini",
        api_url="https://api.openai.com/v1/chat/completions",
        api_key_env="OPENAI_API_KEY",
        input_cost_per_1k=0.00015,
        output_cost_per_1k=0.0006,
    ),
}


@dataclass
class UsageRecord:
    """Tracks token usage and cost for a single API call."""

    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    cost_microdollars: int = 0  # integer microdollars for precision
    timestamp: float = 0.0
    operation_tag: str = ""  # e.g., "diff_analysis", "review", "explain"


class ModelRegistry:
    """Manage available AI providers and track usage/costs."""

    def __init__(self):
        self._usage: List[UsageRecord] = []

    def get_provider(self, name: str) -> Optional[ModelProvider]:
        return PROVIDERS.get(name)

    def is_available(self, name: str) -> bool:
        provider = PROVIDERS.get(name)
        if provider is None:
            return False
        return bool(os.environ.get(provider.api_key_env))

    def record_usage(self, record: UsageRecord) -> None:
        self._usage.append(record)

    @property
    def total_cost(self) -> float:
        return sum(r.cost_usd for r in self._usage)

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self._usage)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self._usage)

    def usage_summary(self) -> Dict:
        return {
            "total_calls": len(self._usage),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost, 6),
            "by_provider": self._usage_by_provider(),
        }

    def _usage_by_provider(self) -> Dict:
        by_provider: Dict[str, Dict] = {}
        for r in self._usage:
            if r.provider not in by_provider:
                by_provider[r.provider] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
            by_provider[r.provider]["calls"] += 1
            by_provider[r.provider]["input_tokens"] += r.input_tokens
            by_provider[r.provider]["output_tokens"] += r.output_tokens
            by_provider[r.provider]["cost_usd"] += r.cost_usd
        return by_provider


class AIClient:
    """Thin API client for LLM calls using stdlib only."""

    def __init__(
        self,
        provider_name: str = "anthropic",
        model: str = "",
        max_cost: float = 1.0,
        registry: Optional[ModelRegistry] = None,
    ):
        self.provider = PROVIDERS.get(provider_name)
        if self.provider is None:
            raise ValueError(f"Unknown provider: {provider_name}")
        self.model = model or self.provider.model
        self.max_cost = max_cost
        self.registry = registry or ModelRegistry()

    def is_available(self) -> bool:
        if self.provider is None:
            return False
        return bool(os.environ.get(self.provider.api_key_env))

    def complete(self, prompt: str, max_tokens: int = 1000, operation_tag: str = "") -> str:
        """Send a prompt and return the response text.

        Tracks usage and enforces cost budget.
        """
        self._current_tag = operation_tag
        if not self.is_available():
            raise RuntimeError(f"API key not set: {self.provider.api_key_env}")

        if self.registry.total_cost >= self.max_cost:
            raise RuntimeError(
                f"Cost budget exceeded: ${self.registry.total_cost:.4f} >= ${self.max_cost}"
            )

        api_key = os.environ[self.provider.api_key_env]

        if self.provider.name == "anthropic":
            return self._call_anthropic(api_key, prompt, max_tokens)
        elif self.provider.name == "openai":
            return self._call_openai(api_key, prompt, max_tokens)
        else:
            raise ValueError(f"No client implementation for: {self.provider.name}")

    def _call_anthropic(self, api_key: str, prompt: str, max_tokens: int) -> str:
        payload = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = Request(
            self.provider.api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())

        text = data.get("content", [{}])[0].get("text", "")
        usage = data.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        cache_read = usage.get("cache_read_input_tokens", 0)

        cost = (
            (input_tokens / 1000) * self.provider.input_cost_per_1k
            + (output_tokens / 1000) * self.provider.output_cost_per_1k
        )
        cost_micro = int(cost * 1_000_000)

        self.registry.record_usage(UsageRecord(
            provider="anthropic",
            model=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cost_usd=cost,
            cost_microdollars=cost_micro,
            timestamp=time.time(),
            operation_tag=getattr(self, "_current_tag", ""),
        ))

        return text

    def _call_openai(self, api_key: str, prompt: str, max_tokens: int) -> str:
        payload = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = Request(
            self.provider.api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )

        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())

        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)

        cost = (
            (input_tokens / 1000) * self.provider.input_cost_per_1k
            + (output_tokens / 1000) * self.provider.output_cost_per_1k
        )

        self.registry.record_usage(UsageRecord(
            provider="openai",
            model=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            timestamp=time.time(),
        ))

        return text
