"""
NEXUS Engine - Autonomous LLM Router & Transport Layer
=====================================================
Architecture Role: Zero-bloat, deterministic transport and routing engine
for Local (Ollama) and Cloud (Google Gemini, Anthropic Claude) LLMs.

Design Invariants:
1. Strict Priority Hierarchy: 1. Security -> 2. Stability & Speed -> 3. Advanced Features.
2. Zero Plaintext Secret Leakage: API keys remain strictly in volatile RAM, never logged,
   never written to config dataclasses, never exposed in __repr__, never passed in URLs.
3. Zero-Bloat HTTP Transport: Uses Python standard library urllib.request + langchain-core
   message contracts, avoiding heavy, conflicting vendor SDK dependencies.
4. Resilient Fault-Tolerance: Graceful offline detection, strict socket timeouts,
   and intelligent retries on transient network failures (429/503/504) with zero retries on 401/403.
5. LangChain Message Interoperability: Seamless normalization of plain dicts and
   LangChain BaseMessage (SystemMessage, HumanMessage, AIMessage) objects.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Structured logging with stdlib fallback
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-LLMRouter")  # type: ignore

# LangChain message contracts
try:
    from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError:
    BaseMessage = Any  # type: ignore
    SystemMessage = Any  # type: ignore
    HumanMessage = Any  # type: ignore
    AIMessage = Any  # type: ignore
    HAS_LANGCHAIN_CORE = False

def mask_secret(secret: Optional[str]) -> str:
    """Masks sensitive values (API tokens, passwords) for security logging."""
    if secret is None:
        return "[EMPTY]"
    cleaned = str(secret).strip()
    if not cleaned:
        return "[EMPTY]"
    if len(cleaned) < 8:
        return "[REDACTED]"
    return f"{'•' * 8}{cleaned[-4:]}"


# ==============================================================================
# EXCEPTION HIERARCHY
# ==============================================================================

class LLMRouterError(Exception):
    """Base exception for all LLM routing, transport, and execution errors."""
    pass


class LLMConnectionError(LLMRouterError):
    """Raised when the host daemon or endpoint is unreachable (e.g., Ollama offline)."""
    pass


class LLMAuthenticationError(LLMRouterError):
    """Raised when an API credential is missing, expired, or invalid (HTTP 401/403)."""
    pass


class LLMTimeoutError(LLMRouterError):
    """Raised when an LLM transport call exceeds the configured timeout budget."""
    pass


class LLMRateLimitError(LLMRouterError):
    """Raised when HTTP 429 rate limit is encountered and retry backoff is exhausted."""
    pass


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class LLMConfig:
    """
    Immutable specification of active LLM parameters.

    SECURITY INVARIANT:
    Raw API keys are intentionally excluded from this dataclass.
    LLMConfig is always 100% safe to serialize, log, or display in telemetry.
    """
    provider: str = "local"                      # "local" or "cloud"
    model: str = "llama3:8b"                     # e.g., "llama3:8b", "gemini-1.5-flash", "claude-3-5-sonnet"
    base_url: str = "http://127.0.0.1:11434"    # Ollama endpoint
    temperature: float = 0.0                     # 0.0 for deterministic SQL generation
    max_tokens: int = 1024
    timeout_sec: float = 45.0

    @classmethod
    def from_sidebar_dict(cls, cfg: Dict[str, Any]) -> LLMConfig:
        """
        Constructs an LLMConfig instance by mapping dictionary fields from
        SidebarPanel.get_llm_config(). Ignores masked or raw API keys.
        """
        raw_provider = str(cfg.get("provider") or cfg.get("mode") or "local").strip().lower()
        provider = "cloud" if "cloud" in raw_provider else "local"

        raw_model = str(cfg.get("model") or cfg.get("selected_model") or "").strip()
        if not raw_model:
            model = "llama3:8b" if provider == "local" else "gemini-1.5-flash"
        else:
            model = raw_model

        base_url = str(cfg.get("base_url") or "http://127.0.0.1:11434").strip()
        temperature = float(cfg.get("temperature", 0.0))
        max_tokens = int(cfg.get("max_tokens", 1024))
        timeout_sec = float(cfg.get("timeout_sec", 45.0))

        return cls(
            provider=provider,
            model=model,
            base_url=base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_sec=timeout_sec,
        )


@dataclasses.dataclass(frozen=True)
class LLMResponse:
    """Standardized response payload returned by all LLM providers."""
    content: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: float
    raw_finish_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to a serializable dictionary."""
        return {
            "content": self.content,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "latency_ms": round(self.latency_ms, 2),
            "raw_finish_reason": self.raw_finish_reason,
        }


# ==============================================================================
# LLM ROUTER & TRANSPORT ENGINE
# ==============================================================================

class LLMRouter:
    """
    Unified router and zero-dependency transport manager for local and cloud LLMs.

    Supported Providers:
    1. Local: Ollama Daemon via /api/chat and /api/tags.
    2. Cloud: Google Gemini via generateContent (x-goog-api-key header authentication).
    3. Cloud: Anthropic Claude via /v1/messages (x-api-key & anthropic-version headers).
    """

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        api_key_provider: Optional[Callable[[], Optional[str]]] = None
    ) -> None:
        """
        Parameters:
            config: Operational LLM parameters (defaults to local llama3:8b).
            api_key_provider: Dynamic callable providing the raw cloud API key from volatile
                              memory on-demand at transport time (never cached in config).
        """
        self.config = config or LLMConfig()
        self._api_key_provider = api_key_provider

    def __repr__(self) -> str:
        """Safe representation with zero risk of secret exposure."""
        has_key = bool(self.get_api_key())
        return (
            f"LLMRouter(provider={self.config.provider!r}, "
            f"model={self.config.model!r}, "
            f"base_url={self.config.base_url!r}, "
            f"temperature={self.config.temperature}, "
            f"has_api_key={has_key})"
        )

    def get_api_key(self) -> Optional[str]:
        """
        Fetches the active cloud API key from the volatile provider callback.
        Restricted to RAM-only access at transport dispatch.
        """
        if callable(self._api_key_provider):
            try:
                key = self._api_key_provider()
                if key and str(key).strip():
                    return str(key).strip()
            except Exception as exc:
                logger.error(f"Error invoking volatile API key provider callback: {exc}")
        return None

    # --------------------------------------------------------------------------
    # SECRET REDACTION & LOGGING SAFEGUARD
    # --------------------------------------------------------------------------

    @staticmethod
    def _scrub_error_message(message: str, api_key: Optional[str]) -> str:
        """
        Replaces any accidental echo of the raw API key in network error messages,
        tracebacks, or HTTP error bodies with mask_secret(api_key).
        """
        if not message:
            return ""
        scrubbed = str(message)
        if api_key and str(api_key).strip():
            raw_key = str(api_key).strip()
            masked = mask_secret(raw_key)

            # Scrub exact raw key
            scrubbed = scrubbed.replace(raw_key, masked)

            # Scrub URL-encoded variant
            url_encoded = urllib.parse.quote(raw_key, safe="")
            if url_encoded != raw_key:
                scrubbed = scrubbed.replace(url_encoded, masked)

        return scrubbed

    # --------------------------------------------------------------------------
    # HEALTH CHECK PROTOCOLS
    # --------------------------------------------------------------------------

    def check_ollama_health(self, timeout_sec: float = 2.0) -> Tuple[bool, List[str], str]:
        """
        Non-raising health inspector for local Ollama daemon.
        Queries /api/tags to verify connectivity and list installed models.

        Returns:
            (is_online: bool, installed_models: List[str], message: str)
        """
        base = self.config.base_url.rstrip("/")
        if not (base.startswith("http://") or base.startswith("https://")):
            return False, [], f"Invalid Ollama base URL scheme: '{base}'. Must start with http:// or https://"

        tags_url = f"{base}/api/tags"
        req = urllib.request.Request(
            tags_url,
            headers={"User-Agent": "NEXUS-LLMRouter/1.0", "Accept": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [
                        m.get("name") for m in data.get("models", [])
                        if isinstance(m, dict) and "name" in m
                    ]
                    return True, models, f"Ollama is online with {len(models)} model(s) available."
                return False, [], f"Ollama returned unexpected HTTP status {resp.status}."
        except urllib.error.HTTPError as exc:
            return False, [], f"Ollama HTTP error {exc.code}: {exc.reason}"
        except urllib.error.URLError as exc:
            return (
                False,
                [],
                f"Ollama daemon is offline or unreachable at {base}. "
                f"Start Ollama with 'ollama serve' or run 'ollama run {self.config.model}'."
            )
        except Exception as exc:
            return False, [], f"Ollama connection check failed: {exc}"

    # --------------------------------------------------------------------------
    # MESSAGE NORMALIZATION
    # --------------------------------------------------------------------------

    @staticmethod
    def _normalize_messages(
        messages: List[Union[Dict[str, str], BaseMessage]],
        system_prompt: Optional[str] = None
    ) -> Tuple[Optional[str], List[Dict[str, str]]]:
        """
        Converts heterogeneous inputs (plain dicts or LangChain BaseMessage objects)
        into a standardized tuple: (effective_system_prompt, list_of_chat_messages).
        """
        extracted_system: List[str] = []
        if system_prompt and system_prompt.strip():
            extracted_system.append(system_prompt.strip())

        chat_messages: List[Dict[str, str]] = []

        for msg in messages:
            role = "user"
            content = ""

            # 1. LangChain BaseMessage Handling
            if HAS_LANGCHAIN_CORE and isinstance(msg, BaseMessage):
                content = str(msg.content)
                if isinstance(msg, SystemMessage) or getattr(msg, "type", "") == "system":
                    extracted_system.append(content)
                    continue
                elif isinstance(msg, AIMessage) or getattr(msg, "type", "") in ("ai", "assistant"):
                    role = "assistant"
                else:
                    role = "user"

            # 2. Standard Dictionary Handling
            elif isinstance(msg, dict):
                content = str(msg.get("content", ""))
                msg_role = str(msg.get("role", "user")).lower()
                if msg_role == "system":
                    extracted_system.append(content)
                    continue
                elif msg_role in ("ai", "assistant", "model"):
                    role = "assistant"
                else:
                    role = "user"

            # 3. String Fallback
            elif isinstance(msg, str):
                content = msg
                role = "user"

            chat_messages.append({"role": role, "content": content})

        combined_system = "\n\n".join(extracted_system).strip() if extracted_system else None
        return combined_system, chat_messages

    # --------------------------------------------------------------------------
    # LOW-LEVEL HTTP TRANSPORT WITH RETRIES
    # --------------------------------------------------------------------------

    def _execute_http_request(
        self,
        req: urllib.request.Request,
        api_key: Optional[str] = None
    ) -> Tuple[bytes, float]:
        """
        Executes HTTP requests with deterministic timeout handling, secret scrubbing,
        and automatic exponential backoff for transient 429/503/504 errors.
        Never retries 401/403 authentication failures or offline connection drops.
        """
        max_retries = 2
        backoff_sec = 1.0

        # Bandit B310 hardening: enforce strict http/https URI scheme
        if not req.full_url.startswith(("http://", "https://")):
            raise LLMRouterError(
                f"Unsupported or dangerous URI scheme in URL: '{req.full_url}'. Only 'http://' and 'https://' are permitted."
            )

        for attempt in range(max_retries + 1):
            t_start = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_sec) as resp:
                    data = resp.read()
                    latency_ms = (time.perf_counter() - t_start) * 1000.0
                    return data, latency_ms

            except urllib.error.HTTPError as exc:
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    pass

                scrubbed_msg = self._scrub_error_message(
                    f"HTTP {exc.code} {exc.reason}: {error_body}", api_key
                )

                # Authentication failures: FAIL FAST (zero retries)
                if exc.code in (401, 403):
                    logger.error(f"[AUTH ERROR] {scrubbed_msg}")
                    raise LLMAuthenticationError(scrubbed_msg) from exc

                # Rate limits and transient server errors: RETRY WITH BACKOFF
                if exc.code in (429, 502, 503, 504):
                    if attempt < max_retries:
                        logger.warning(
                            f"[TRANSIENT {exc.code}] Retrying in {backoff_sec:.1f}s "
                            f"(Attempt {attempt + 1}/{max_retries})..."
                        )
                        time.sleep(backoff_sec)
                        backoff_sec *= 2.0
                        continue
                    else:
                        if exc.code == 429:
                            raise LLMRateLimitError(scrubbed_msg) from exc
                        raise LLMRouterError(scrubbed_msg) from exc

                # All other 4xx/5xx: FAIL FAST
                raise LLMRouterError(scrubbed_msg) from exc

            except urllib.error.URLError as exc:
                reason_str = str(exc.reason)
                scrubbed_reason = self._scrub_error_message(f"URL Error: {reason_str}", api_key)

                # Timeout checks
                if isinstance(exc.reason, socket.timeout) or "timed out" in reason_str.lower():
                    raise LLMTimeoutError(
                        f"Request to {req.full_url} timed out after {self.config.timeout_sec}s."
                    ) from exc

                # Connection refused checks (Ollama daemon offline)
                if (
                    isinstance(exc.reason, ConnectionRefusedError)
                    or "connection refused" in reason_str.lower()
                    or "winerror 10061" in reason_str.lower()
                ):
                    raise LLMConnectionError(
                        f"Connection refused at {req.full_url}. Verify local daemon is running."
                    ) from exc

                raise LLMConnectionError(scrubbed_reason) from exc

            except (socket.timeout, TimeoutError) as exc:
                raise LLMTimeoutError(
                    f"Socket timed out after {self.config.timeout_sec}s for {req.full_url}."
                ) from exc

            except Exception as exc:
                scrubbed_err = self._scrub_error_message(str(exc), api_key)
                raise LLMRouterError(f"Unexpected transport failure: {scrubbed_err}") from exc

        raise LLMRouterError("Request retry loop exhausted unexpectedly.")

    # --------------------------------------------------------------------------
    # LOCAL OLLAMA TRANSPORT
    # --------------------------------------------------------------------------

    def _invoke_ollama(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str],
        temperature: Optional[float],
        json_mode: bool
    ) -> LLMResponse:
        """Executes prompt against local Ollama /api/chat endpoint."""
        base = self.config.base_url.rstrip("/")
        chat_url = f"{base}/api/chat"

        # Build message history with system message if present
        ollama_messages: List[Dict[str, str]] = []
        if system_prompt:
            ollama_messages.append({"role": "system", "content": system_prompt})
        ollama_messages.extend(messages)

        temp = temperature if temperature is not None else self.config.temperature
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_predict": self.config.max_tokens,
            }
        }
        if json_mode:
            payload["format"] = "json"

        req = urllib.request.Request(
            chat_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "NEXUS-LLMRouter/1.0"}
        )

        resp_bytes, latency_ms = self._execute_http_request(req)
        try:
            resp_data = json.loads(resp_bytes.decode("utf-8"))
        except Exception as exc:
            raise LLMRouterError(f"Ollama returned malformed JSON: {exc}") from exc

        content = resp_data.get("message", {}).get("content", "")
        prompt_tokens = int(resp_data.get("prompt_eval_count", 0))
        completion_tokens = int(resp_data.get("eval_count", 0))
        total_tokens = prompt_tokens + completion_tokens
        finish_reason = resp_data.get("done_reason")

        return LLMResponse(
            content=content,
            provider="local",
            model=self.config.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=latency_ms,
            raw_finish_reason=finish_reason,
        )

    # --------------------------------------------------------------------------
    # GOOGLE GEMINI TRANSPORT
    # --------------------------------------------------------------------------

    def _invoke_gemini(
        self,
        api_key: str,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str],
        temperature: Optional[float],
        json_mode: bool
    ) -> LLMResponse:
        """
        Executes prompt against Google Gemini generateContent endpoint.

        SECURITY GUARANTEE:
        The API key is strictly transmitted via the 'x-goog-api-key' HTTP header.
        The URL NEVER contains '?key=', preventing key leakage in proxy logs or error URLs.
        """
        if not re.fullmatch(r"[A-Za-z0-9._-]+", self.config.model):
            raise LLMRouterError(
                f"Invalid characters in Gemini model identifier: '{self.config.model}'. Only alphanumeric, '.', '_', and '-' are permitted."
            )

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:generateContent"

        contents = []
        for m in messages:
            # Gemini roles: "user" and "model"
            role = "model" if m["role"] == "assistant" else "user"
            contents.append({
                "role": role,
                "parts": [{"text": m["content"]}]
            })

        if not contents:
            contents = [{"role": "user", "parts": [{"text": "Hello"}]}]

        temp = temperature if temperature is not None else self.config.temperature
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": self.config.max_tokens,
            }
        }
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}]
            }
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
                "User-Agent": "NEXUS-LLMRouter/1.0"
            }
        )

        resp_bytes, latency_ms = self._execute_http_request(req, api_key=api_key)
        try:
            resp_data = json.loads(resp_bytes.decode("utf-8"))
        except Exception as exc:
            raise LLMRouterError(f"Gemini returned malformed JSON: {exc}") from exc

        candidates = resp_data.get("candidates", [])
        if not candidates:
            # Handle prompt safety blocks or empty candidates
            prompt_feedback = resp_data.get("promptFeedback", {})
            block_reason = prompt_feedback.get("blockReason", "Unknown")
            raise LLMRouterError(f"Gemini generation blocked: {block_reason}")

        candidate = candidates[0]
        parts = candidate.get("content", {}).get("parts", [])
        content = "".join([p.get("text", "") for p in parts if isinstance(p, dict)])

        usage = resp_data.get("usageMetadata", {})
        prompt_tokens = int(usage.get("promptTokenCount", 0))
        completion_tokens = int(usage.get("candidatesTokenCount", 0))
        total_tokens = int(usage.get("totalTokenCount", prompt_tokens + completion_tokens))
        finish_reason = candidate.get("finishReason")

        return LLMResponse(
            content=content,
            provider="cloud",
            model=self.config.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=latency_ms,
            raw_finish_reason=finish_reason,
        )

    # --------------------------------------------------------------------------
    # ANTHROPIC CLAUDE TRANSPORT
    # --------------------------------------------------------------------------

    def _invoke_claude(
        self,
        api_key: str,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str],
        temperature: Optional[float],
        json_mode: bool
    ) -> LLMResponse:
        """
        Executes prompt against Anthropic Messages API.
        Transmits credentials via 'x-api-key' and 'anthropic-version' headers.
        """
        endpoint = "https://api.anthropic.com/v1/messages"

        claude_messages = [
            {"role": m["role"], "content": m["content"]}
            for m in messages if m["role"] in ("user", "assistant")
        ]

        # Enforce that messages cannot be empty for Anthropic
        if not claude_messages:
            claude_messages = [{"role": "user", "content": "Hello"}]

        temp = temperature if temperature is not None else self.config.temperature
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": temp,
            "messages": claude_messages,
        }
        effective_system = system_prompt or ""
        if json_mode:
            json_directive = "Respond ONLY with a single valid JSON object. Do not include markdown fences or explanatory text."
            effective_system = f"{effective_system}\n\n{json_directive}".strip()

        if effective_system:
            payload["system"] = effective_system

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "NEXUS-LLMRouter/1.0"
            }
        )

        resp_bytes, latency_ms = self._execute_http_request(req, api_key=api_key)
        try:
            resp_data = json.loads(resp_bytes.decode("utf-8"))
        except Exception as exc:
            raise LLMRouterError(f"Anthropic returned malformed JSON: {exc}") from exc

        content_blocks = resp_data.get("content", [])
        content = "".join([b.get("text", "") for b in content_blocks if b.get("type") == "text"])

        usage = resp_data.get("usage", {})
        prompt_tokens = int(usage.get("input_tokens", 0))
        completion_tokens = int(usage.get("output_tokens", 0))
        total_tokens = prompt_tokens + completion_tokens
        finish_reason = resp_data.get("stop_reason")

        return LLMResponse(
            content=content,
            provider="cloud",
            model=self.config.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=latency_ms,
            raw_finish_reason=finish_reason,
        )

    # --------------------------------------------------------------------------
    # PUBLIC INVOCATION API
    # --------------------------------------------------------------------------

    def invoke(
        self,
        messages: List[Union[Dict[str, str], BaseMessage]],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        json_mode: bool = False
    ) -> LLMResponse:
        """
        Dispatches chat messages to the configured provider with full LangChain compatibility.

        Parameters:
            messages: List of dicts or LangChain BaseMessage instances (SystemMessage, HumanMessage, AIMessage).
            system_prompt: Optional top-level system instruction.
            temperature: Optional override for generation temperature.
            json_mode: When True, enforces structured JSON output.

        Returns:
            LLMResponse containing generated content, token metrics, and latency.
        """
        effective_system, normalized_chat = self._normalize_messages(messages, system_prompt)

        provider = self.config.provider.lower()
        if provider == "local":
            return self._invoke_ollama(
                messages=normalized_chat,
                system_prompt=effective_system,
                temperature=temperature,
                json_mode=json_mode
            )

        elif provider == "cloud":
            api_key = self.get_api_key()
            if not api_key:
                raise LLMAuthenticationError(
                    "Cloud API key is missing. Please configure your API key in the sidebar."
                )

            model_lower = self.config.model.lower()
            if "gemini" in model_lower:
                return self._invoke_gemini(
                    api_key=api_key,
                    messages=normalized_chat,
                    system_prompt=effective_system,
                    temperature=temperature,
                    json_mode=json_mode
                )
            elif "claude" in model_lower:
                return self._invoke_claude(
                    api_key=api_key,
                    messages=normalized_chat,
                    system_prompt=effective_system,
                    temperature=temperature,
                    json_mode=json_mode
                )
            else:
                raise LLMRouterError(
                    f"Unsupported cloud model '{self.config.model}'. "
                    f"NEXUS currently supports Google Gemini ('gemini-*') and Anthropic Claude ('claude-*')."
                )

        else:
            raise LLMRouterError(
                f"Unknown LLM provider: '{self.config.provider}'. Allowed values are 'local' or 'cloud'."
            )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        json_mode: bool = False
    ) -> LLMResponse:
        """
        Convenience execution helper for single-turn prompt interactions.
        """
        return self.invoke(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=system_prompt,
            temperature=temperature,
            json_mode=json_mode
        )
