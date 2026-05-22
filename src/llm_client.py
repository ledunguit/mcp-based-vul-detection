"""LLM Client - Unified interface for Claude API and Local LLM."""

from typing import Any
import json
import os

from src.config import (
    LLM_PROVIDER,
    ANTHROPIC_API_KEY,
    CLAUDE_MODEL,
    LOCAL_LLM_BASE_URL,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_API_KEY,
    MAX_TOKENS,
    TEMPERATURE,
)


class LLMClient:
    """Unified LLM client supporting Claude and local OpenAI-compatible endpoints."""
    
    def __init__(self, provider: str | None = None):
        self.provider = self._normalize_provider(provider or LLM_PROVIDER)
        self._client = None
        self.model = ""
        self._init_client()
    
    def _init_client(self):
        """Initialize the appropriate client based on provider."""
        if self.provider == "claude":
            import anthropic
            self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            self.model = CLAUDE_MODEL
        elif self.provider == "local":
            from openai import OpenAI
            self._client = OpenAI(
                base_url=LOCAL_LLM_BASE_URL,
                api_key=LOCAL_LLM_API_KEY,
            )
            self.model = self._resolve_local_model()
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}")

    def _normalize_provider(self, provider: str | None) -> str:
        value = (provider or "auto").strip().lower()
        if value in {"local", "openai", "openai_compatible", "openai-compatible"}:
            return "local"
        if value == "auto":
            has_anthropic_key = bool(ANTHROPIC_API_KEY.strip())
            local_base_url = (LOCAL_LLM_BASE_URL or "").strip()
            if local_base_url and local_base_url != "http://127.0.0.1:1234/v1" and not has_anthropic_key:
                return "local"
            if has_anthropic_key:
                return "claude"
            return "local"
        return value

    def _resolve_local_model(self) -> str:
        configured = (LOCAL_LLM_MODEL or "").strip()
        if configured and configured != "local-model":
            return configured

        preferred = os.getenv("LOCAL_LLM_MODEL_PREFERRED", "").strip()
        models = self._list_local_models()
        if preferred and preferred in models:
            return preferred
        if configured and configured in models:
            return configured
        if models:
            return models[0]
        if configured:
            return configured
        raise ValueError(
            "No local LLM model configured and the OpenAI-compatible endpoint did not return any models."
        )

    def _list_local_models(self) -> list[str]:
        try:
            response = self._client.models.list()
        except Exception:
            return []
        result: list[str] = []
        for item in getattr(response, "data", []) or []:
            model_id = getattr(item, "id", None)
            if model_id:
                result.append(str(model_id))
        return result
    
    def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> "LLMResponse":
        """
        Send a chat completion request.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system prompt
            tools: Optional list of tool definitions
            max_tokens: Max tokens to generate
            temperature: Sampling temperature
        
        Returns:
            LLMResponse with text content and tool calls
        """
        max_tokens = max_tokens or MAX_TOKENS
        temperature = temperature if temperature is not None else TEMPERATURE
        
        if self.provider == "claude":
            return self._chat_claude(messages, system, tools, max_tokens, temperature)
        else:
            return self._chat_openai(messages, system, tools, max_tokens, temperature)
    
    def _chat_claude(
        self,
        messages: list[dict],
        system: str | None,
        tools: list[dict] | None,
        max_tokens: int,
        temperature: float,
    ) -> "LLMResponse":
        """Chat using Claude API."""
        kwargs = {
            "model": CLAUDE_MODEL,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        
        response = self._client.messages.create(**kwargs)
        
        # Extract content
        text = ""
        tool_calls = []
        
        for block in response.content:
            if hasattr(block, "text"):
                text += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input,
                })
        
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            raw_response=response,
        )
    
    def _chat_openai(
        self,
        messages: list[dict],
        system: str | None,
        tools: list[dict] | None,
        max_tokens: int,
        temperature: float,
    ) -> "LLMResponse":
        """Chat using OpenAI-compatible API (local LLM)."""
        # Build messages with system prompt
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        
        kwargs = {
            "model": self.model,
            "messages": all_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        
        # Convert tools to OpenAI format if provided
        if tools:
            openai_tools = []
            for tool in tools:
                openai_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("input_schema", {}),
                    }
                })
            kwargs["tools"] = openai_tools
            kwargs["tool_choice"] = "auto"
        
        response = self._client.chat.completions.create(**kwargs)
        
        # Extract content
        message = response.choices[0].message
        text = message.content or ""
        tool_calls = []
        
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments) if tc.function.arguments else {},
                })
        
        stop_reason = response.choices[0].finish_reason
        if stop_reason == "tool_calls":
            stop_reason = "tool_use"
        
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw_response=response,
        )
    
    def add_tool_results(
        self,
        messages: list[dict],
        assistant_content: Any,
        tool_results: list[dict],
    ) -> list[dict]:
        """
        Add tool results to the message history.
        
        Args:
            messages: Current message history
            assistant_content: The assistant's response that contained tool calls
            tool_results: List of tool result dicts with 'tool_id' and 'content'
        
        Returns:
            Updated message list
        """
        if self.provider == "claude":
            # Claude format
            messages.append({"role": "assistant", "content": assistant_content})
            tool_result_content = [
                {
                    "type": "tool_result",
                    "tool_use_id": tr["tool_id"],
                    "content": tr["content"],
                }
                for tr in tool_results
            ]
            messages.append({"role": "user", "content": tool_result_content})
        else:
            # OpenAI format
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tr["tool_id"],
                        "type": "function",
                        "function": {"name": tr.get("name", ""), "arguments": "{}"}
                    }
                    for tr in tool_results
                ]
            })
            for tr in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tr["tool_id"],
                    "content": tr["content"],
                })
        
        return messages


class LLMResponse:
    """Response from LLM chat completion."""
    
    def __init__(
        self,
        text: str,
        tool_calls: list[dict],
        stop_reason: str,
        raw_response: Any,
    ):
        self.text = text
        self.tool_calls = tool_calls
        self.stop_reason = stop_reason
        self.raw_response = raw_response
    
    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0 or self.stop_reason == "tool_use"
