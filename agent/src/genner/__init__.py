
from typing import Callable
import os  

from anthropic import Anthropic
from openai import OpenAI

from src.client.openrouter import OpenRouter
from src.config import (
    ClaudeConfig,
    DeepseekConfig,
    OAIConfig,
    OllamaConfig,
    OpenRouterConfig,
    GoogleGeminiConfig,  
)
from src.genner.Claude import ClaudeGenner
from src.genner.OAI import OAIGenner
from src.genner.OR import OpenRouterGenner
from src.genner.GoogleGemini import GoogleGeminiGenner  # ADD THIS

from .Base import Genner
from .Deepseek import DeepseekGenner
from .Qwen import QwenGenner

__all__ = ["get_genner", "QwenGenner", "OllamaConfig"]


class BackendException(Exception):
    pass


class DeepseekBackendException(Exception):
    pass


class ClaudeBackendException(Exception):
    pass


available_backends = [
    "deepseek",
    "deepseek_or",
    "deepseek_v3",
    "deepseek_v3_or",
    "openai",
    "gemini",
    "claude",
    "qwq",
    "gemini_direct"  
]


def get_genner(
    backend: str,
    stream_fn: Callable[[str], None] | None,
    deepseek_deepseek_client: OpenAI | None = None,
    deepseek_local_client: OpenAI | None = None,
    anthropic_client: Anthropic | None = None,
    or_client: OpenRouter | None = None,
    llama_client: OpenAI | None = None,
    deepseek_config: DeepseekConfig = DeepseekConfig(),
    claude_config: ClaudeConfig = ClaudeConfig(),
    openai_config: OpenRouterConfig = OpenRouterConfig(),
    gemini_config: OpenRouterConfig = OpenRouterConfig(),
    llama_config: OAIConfig = OAIConfig(),
    qwq_config: OpenRouterConfig = OpenRouterConfig(),
) -> Genner:

    if backend == "deepseek":
        deepseek_config.model = "deepseek-reasoner"
        if not deepseek_deepseek_client:
            raise DeepseekBackendException(
                "Using backend 'deepseek', DeepSeek (openai) client is not provided."
            )

        return DeepseekGenner(deepseek_deepseek_client, deepseek_config, stream_fn)
    elif backend == "deepseek_or":
        deepseek_config.model = "deepseek/deepseek-r1"
        deepseek_config.max_tokens = 32768
        if not or_client:
            raise DeepseekBackendException(
                "Using backend 'deepseek_or', OpenRouter client is not provided."
            )

        return DeepseekGenner(or_client, deepseek_config, stream_fn)
    elif backend == "deepseek_v3":
        deepseek_config.model = "deepseek/deepseek-chat"
        deepseek_config.max_tokens = 32768

        if not or_client:
            raise DeepseekBackendException(
                "Using backend 'deepseek_v3', OpenRouter client is not provided."
            )

        return DeepseekGenner(or_client, deepseek_config, stream_fn)
    elif backend == "local":
        deepseek_config.model = "../DeepSeek-R1-Q4_K_M/DeepSeek-R1-Q4_K_M/DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"

        if not deepseek_local_client:
            raise DeepseekBackendException(
                "Using backend 'deepseek', DeepSeek Local (openai) client is not provided."
            )

        return DeepseekGenner(deepseek_local_client, deepseek_config, stream_fn)
    elif backend == "claude":
        if not anthropic_client:
            raise ClaudeBackendException(
                "Using backend 'claude', Anthropic client is not provided."
            )

        return ClaudeGenner(anthropic_client, claude_config, stream_fn)
    elif backend == "openai":
        openai_config.name = "openai/gpt-4o-mini"  
        openai_config.model = "openai/gpt-4o-mini"   

        if not or_client:
            return OAIGenner(
                client=OpenAI(),
                config=OAIConfig(name=openai_config.name, model=openai_config.model),
                stream_fn=stream_fn,
            )

        return OpenRouterGenner(or_client, openai_config, stream_fn)
    elif backend == "deepseek_v3_or":
        deepseek_config.model = "deepseek/deepseek-chat"
        deepseek_config.max_tokens = 32768
        deepseek_config.temperature = 0

        if not or_client:
            raise DeepseekBackendException(
                "Using backend 'deepseek_v3_or', OpenRouter client is not provided."
            )

        return DeepseekGenner(or_client, deepseek_config, stream_fn)
    elif backend == "gemini":
        gemini_config.name = "google/gemini-2.5-pro-preview-06-05"
        gemini_config.model = "google/gemini-2.5-pro-preview-06-05"

        if not or_client:
            raise Exception(
                "Using backend 'gemini', OpenRouter client is not provided."
            )

        return OpenRouterGenner(or_client, gemini_config, stream_fn)
    elif backend == "llama":
        llama_config.name = "NousResearch/Meta-Llama-3-8B"
        llama_config.model = "NousResearch/Meta-Llama-3-8B"

        if not llama_client:
            raise Exception("Using backend 'llama', Llama client is not provided.")

        return OAIGenner(llama_client, llama_config, stream_fn)
    elif backend == "qwq":
        qwq_config.name = "qwen/qwq-32b"
        qwq_config.model = "qwen/qwq-32b"

        if not or_client:
            raise Exception("Using backend 'qwq', OpenRouter client is not provided.")

        return OpenRouterGenner(or_client, qwq_config, stream_fn)
    
    elif backend == "gemini_direct":
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise Exception("GOOGLE_API_KEY required for direct Gemini access.")
        
        config = GoogleGeminiConfig()
        config.model = "gemini-1.5-pro"
        return GoogleGeminiGenner(google_api_key, config, stream_fn)

    raise BackendException(
        f"Unsupported backend: {backend}, available backends: {', '.join(available_backends)}"
    )