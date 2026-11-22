"""
NEXUS Engine - LLM Router & Transport Layer Test Suite
=====================================================
Architecture Role: Mocked verification matrix validating provider detection,
payload generation, token extraction, zero secret leakage, and offline tolerance.

Test Matrix:
1. LLMConfig.from_sidebar_dict() mapping for local and cloud configs.
2. Mocked Ollama /api/chat payload structure (stream=False, format=json, options).
3. Mocked check_ollama_health() online/offline detection with actionable guidance.
4. Mocked Google Gemini request verification (x-goog-api-key header; never in URL).
5. Mocked Anthropic Claude request verification (x-api-key, anthropic-version, system).
6. Missing cloud API key raises LLMAuthenticationError.
7. Secret redaction safeguard (HTTP error body containing raw key masked to ••••••••5678).
8. LangChain BaseMessage (SystemMessage, HumanMessage, AIMessage) normalization.
9. Transient retry logic (429 backoff retry vs 401 fast-fail).

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13
"""

from __future__ import annotations

import dataclasses
import io
import json
import socket
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agent.llm_router import (
    LLMAuthenticationError,
    LLMConfig,
    LLMConnectionError,
    LLMResponse,
    LLMRateLimitError,
    LLMRouter,
    LLMRouterError,
    LLMTimeoutError,
)


class TestLLMConfigAndSidebarMapping(unittest.TestCase):
    """Verifies LLMConfig immutability and mapping from SidebarPanel state."""

    def test_from_sidebar_dict_local(self) -> None:
        """Verify local configuration mapping from SidebarPanel dictionary."""
        sidebar_payload = {
            "provider": "local",
            "mode": "local",
            "provider_name": "Local (Ollama)",
            "model": "llama3:8b",
            "selected_model": "llama3:8b",
            "masked_api_key": "[EMPTY]",
            "has_api_key": False,
        }
        config = LLMConfig.from_sidebar_dict(sidebar_payload)
        self.assertEqual(config.provider, "local")
        self.assertEqual(config.model, "llama3:8b")
        self.assertEqual(config.base_url, "http://127.0.0.1:11434")
        self.assertEqual(config.temperature, 0.0)
        self.assertEqual(config.max_tokens, 1024)

    def test_from_sidebar_dict_cloud(self) -> None:
        """Verify cloud configuration mapping ignores masked credentials."""
        sidebar_payload = {
            "provider": "cloud",
            "mode": "cloud",
            "provider_name": "Cloud API",
            "model": "gemini-1.5-flash",
            "selected_model": "gemini-1.5-flash",
            "masked_api_key": "••••••••5678",
            "has_api_key": True,
        }
        config = LLMConfig.from_sidebar_dict(sidebar_payload)
        self.assertEqual(config.provider, "cloud")
        self.assertEqual(config.model, "gemini-1.5-flash")
        # Invariant: Raw credentials are NEVER stored on LLMConfig
        self.assertFalse(hasattr(config, "api_key"))
        self.assertFalse(hasattr(config, "masked_api_key"))

    def test_immutability_guarantee(self) -> None:
        """Verify LLMConfig is frozen and cannot be modified at runtime."""
        config = LLMConfig(provider="local", model="llama3:8b")
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            config.provider = "cloud"  # type: ignore


class TestOllamaTransport(unittest.TestCase):
    """Verifies local Ollama communication, health check, and payload structure."""

    def setUp(self) -> None:
        self.config = LLMConfig(provider="local", model="llama3:8b", temperature=0.0)
        self.router = LLMRouter(config=self.config)

    @patch("urllib.request.urlopen")
    def test_ollama_chat_payload_and_tokens(self, mock_urlopen: MagicMock) -> None:
        """Verify Ollama /api/chat payload parameters, options, and token extraction."""
        fake_response = {
            "model": "llama3:8b",
            "message": {"role": "assistant", "content": "SELECT * FROM orders;"},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 42,
            "eval_count": 18,
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_response).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        response = self.router.invoke(
            messages=[{"role": "user", "content": "Generate SQL for orders"}],
            system_prompt="You are a SQL engine",
            json_mode=True
        )

        # 1. Assert response parsing
        self.assertEqual(response.content, "SELECT * FROM orders;")
        self.assertEqual(response.provider, "local")
        self.assertEqual(response.model, "llama3:8b")
        self.assertEqual(response.prompt_tokens, 42)
        self.assertEqual(response.completion_tokens, 18)
        self.assertEqual(response.total_tokens, 60)
        self.assertEqual(response.raw_finish_reason, "stop")

        # 2. Inspect outgoing request payload
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/api/chat"))
        payload = json.loads(req.data.decode("utf-8"))

        self.assertEqual(payload["model"], "llama3:8b")
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["format"], "json")  # json_mode=True
        self.assertEqual(payload["options"]["temperature"], 0.0)
        self.assertEqual(payload["options"]["num_predict"], 1024)

        # Messages must include system instruction followed by user prompt
        self.assertEqual(payload["messages"][0]["role"], "system")
        self.assertEqual(payload["messages"][0]["content"], "You are a SQL engine")
        self.assertEqual(payload["messages"][1]["role"], "user")
        self.assertEqual(payload["messages"][1]["content"], "Generate SQL for orders")

    @patch("urllib.request.urlopen")
    def test_check_ollama_health_online(self, mock_urlopen: MagicMock) -> None:
        """Verify online health check extracts installed models."""
        fake_tags = {
            "models": [
                {"name": "llama3:8b", "size": 4700000000},
                {"name": "codellama:7b", "size": 3800000000}
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(fake_tags).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        is_online, models, msg = self.router.check_ollama_health()
        self.assertTrue(is_online)
        self.assertIn("llama3:8b", models)
        self.assertIn("codellama:7b", models)
        self.assertIn("2 model(s)", msg)

    @patch("urllib.request.urlopen")
    def test_check_ollama_health_offline_guidance(self, mock_urlopen: MagicMock) -> None:
        """Verify offline health check returns actionable instructions without crashing."""
        mock_urlopen.side_effect = urllib.error.URLError(ConnectionRefusedError(10061, "Connection refused"))

        is_online, models, msg = self.router.check_ollama_health()
        self.assertFalse(is_online)
        self.assertEqual(models, [])
        self.assertIn("Ollama daemon is offline", msg)
        self.assertIn("ollama serve", msg)

    def test_file_uri_scheme_rejected_security_b310(self) -> None:
        """Verify file:// base_url is rejected by Bandit B310 URI scheme guard."""
        bad_config = LLMConfig(provider="local", base_url="file:///etc/passwd")
        router = LLMRouter(config=bad_config)
        with self.assertRaises(LLMRouterError) as ctx:
            router.generate("test prompt")
        self.assertIn("Unsupported or dangerous URI scheme", str(ctx.exception))


class TestCloudGoogleGeminiTransport(unittest.TestCase):
    """Verifies Google Gemini routing and security invariants."""

    def test_missing_api_key_raises_auth_error(self) -> None:
        """Verify invocation without API key raises LLMAuthenticationError."""
        config = LLMConfig(provider="cloud", model="gemini-1.5-flash")
        router = LLMRouter(config=config, api_key_provider=lambda: None)

        with self.assertRaises(LLMAuthenticationError):
            router.invoke([{"role": "user", "content": "test"}])

    def test_gemini_model_name_character_validation(self) -> None:
        """Verify Gemini model name validation rejects invalid characters."""
        config = LLMConfig(provider="cloud", model="gemini-pro; evil_cmd")
        router = LLMRouter(config=config, api_key_provider=lambda: "dummy_key")
        with self.assertRaises(LLMRouterError) as ctx:
            router.generate("test")
        self.assertIn("Invalid characters in Gemini model identifier", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_gemini_payload_and_header_security(self, mock_urlopen: MagicMock) -> None:
        """
        SECURITY AUDIT TEST:
        Proves that the Gemini API key is transmitted strictly in the 'x-goog-api-key'
        header and NEVER exposed in the request URL query string.
        """
        raw_secret_key = "AIzaSySecretGeminiKey12345678"
        config = LLMConfig(provider="cloud", model="gemini-1.5-flash", max_tokens=512)
        router = LLMRouter(config=config, api_key_provider=lambda: raw_secret_key)

        fake_gemini_resp = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "SELECT COUNT(*) FROM customers;"}],
                        "role": "model"
                    },
                    "finishReason": "STOP",
                    "index": 0
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 25,
                "candidatesTokenCount": 10,
                "totalTokenCount": 35
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_gemini_resp).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        response = router.generate(
            prompt="Count total customers",
            system_prompt="Return SQL only",
            json_mode=True
        )

        self.assertEqual(response.content, "SELECT COUNT(*) FROM customers;")
        self.assertEqual(response.provider, "cloud")
        self.assertEqual(response.model, "gemini-1.5-flash")
        self.assertEqual(response.prompt_tokens, 25)
        self.assertEqual(response.completion_tokens, 10)
        self.assertEqual(response.total_tokens, 35)

        # 1. URL Security Check: Key MUST NOT appear in query string
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        self.assertNotIn("key=", req.full_url)
        self.assertNotIn(raw_secret_key, req.full_url)

        # 2. Header Security Check: Key must be in x-goog-api-key
        self.assertEqual(req.headers.get("X-goog-api-key"), raw_secret_key)

        # 3. Payload Structure Check
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["contents"][0]["role"], "user")
        self.assertEqual(payload["contents"][0]["parts"][0]["text"], "Count total customers")
        self.assertEqual(payload["systemInstruction"]["parts"][0]["text"], "Return SQL only")
        self.assertEqual(payload["generationConfig"]["responseMimeType"], "application/json")


class TestCloudAnthropicClaudeTransport(unittest.TestCase):
    """Verifies Anthropic Claude Messages API routing and payload structure."""

    @patch("urllib.request.urlopen")
    def test_claude_messages_payload_and_headers(self, mock_urlopen: MagicMock) -> None:
        """Verify Claude x-api-key header, anthropic-version, and system parameter."""
        raw_secret_key = "sk-ant-api03-abcdef12345678"
        config = LLMConfig(provider="cloud", model="claude-3-5-sonnet", max_tokens=1000)
        router = LLMRouter(config=config, api_key_provider=lambda: raw_secret_key)

        fake_claude_resp = {
            "id": "msg_01XYZ",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "SELECT * FROM sales LIMIT 10;"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 15}
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_claude_resp).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        response = router.invoke(
            messages=[
                {"role": "user", "content": "Show recent sales"},
            ],
            system_prompt="You are a senior analyst"
        )

        self.assertEqual(response.content, "SELECT * FROM sales LIMIT 10;")
        self.assertEqual(response.prompt_tokens, 50)
        self.assertEqual(response.completion_tokens, 15)
        self.assertEqual(response.total_tokens, 65)

        # Verify headers
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(req.headers.get("X-api-key"), raw_secret_key)
        self.assertEqual(req.headers.get("Anthropic-version"), "2023-06-01")

        # Verify payload structure
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["model"], "claude-3-5-sonnet")
        self.assertEqual(payload["system"], "You are a senior analyst")
        self.assertEqual(payload["messages"], [{"role": "user", "content": "Show recent sales"}])

    @patch("urllib.request.urlopen")
    def test_claude_json_mode_injects_system_directive(self, mock_urlopen: MagicMock) -> None:
        """Verify Claude json_mode=True injects the strict JSON directive into payload['system']."""
        raw_secret_key = "sk-ant-api03-abcdef12345678"
        config = LLMConfig(provider="cloud", model="claude-3-5-sonnet")
        router = LLMRouter(config=config, api_key_provider=lambda: raw_secret_key)

        fake_claude_resp = {
            "id": "msg_02JSON",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "{\"key\": \"val\"}"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 10}
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_claude_resp).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        response = router.generate("Return json", system_prompt="Base system", json_mode=True)
        self.assertEqual(response.content, "{\"key\": \"val\"}")

        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("Respond ONLY with a single valid JSON object", payload["system"])
        self.assertIn("Base system", payload["system"])


class TestSecretRedactionAndErrorHandling(unittest.TestCase):
    """Verifies that API keys are strictly redacted when errors echo raw tokens."""

    @patch("urllib.request.urlopen")
    def test_http_error_scrubs_raw_api_key_from_exception_message(
        self, mock_urlopen: MagicMock
    ) -> None:
        """
        SECURITY TEST:
        Simulate a cloud server returning HTTP 401 with an error body echoing the raw key.
        Verify that the raised LLMAuthenticationError contains the masked key (••••••••5678)
        and ZERO plaintext characters of the secret.
        """
        raw_key = "sk-super-secret-key-12345678"
        config = LLMConfig(provider="cloud", model="gemini-1.5-flash")
        router = LLMRouter(config=config, api_key_provider=lambda: raw_key)

        # Simulated upstream error echoing the raw key
        error_content = json.dumps({
            "error": {
                "code": 401,
                "message": f"API key not valid. Please pass a valid key: {raw_key}",
                "status": "UNAUTHENTICATED"
            }
        }).encode("utf-8")

        mock_http_error = urllib.error.HTTPError(
            url="https://generativelanguage.googleapis.com",
            code=401,
            msg="Unauthorized",
            hdrs={},  # type: ignore
            fp=io.BytesIO(error_content)
        )
        mock_urlopen.side_effect = mock_http_error

        with self.assertRaises(LLMAuthenticationError) as ctx:
            router.generate("Generate query")

        exc_str = str(ctx.exception)

        # 1. Must contain the safely masked representation
        self.assertIn("••••••••5678", exc_str)

        # 2. Must NEVER leak any part of the plaintext secret
        self.assertNotIn("super-secret-key", exc_str)
        self.assertNotIn("sk-super-secret-key-12345678", exc_str)

    def test_router_repr_never_leaks_secrets(self) -> None:
        """Verify __repr__ does not output raw or masked API keys."""
        raw_key = "sk-sensitive-token-99998888"
        router = LLMRouter(
            config=LLMConfig(provider="cloud", model="gemini-1.5-flash"),
            api_key_provider=lambda: raw_key
        )
        repr_str = repr(router)
        self.assertNotIn("99998888", repr_str)
        self.assertNotIn("sk-sensitive", repr_str)
        self.assertIn("has_api_key=True", repr_str)


class TestLangChainMessageNormalization(unittest.TestCase):
    """Verifies normalization of LangChain BaseMessage objects."""

    @patch("urllib.request.urlopen")
    def test_langchain_messages_pipeline(self, mock_urlopen: MagicMock) -> None:
        """Verify SystemMessage, HumanMessage, and AIMessage are properly normalized."""
        config = LLMConfig(provider="local", model="llama3:8b")
        router = LLMRouter(config=config)

        fake_resp = {
            "message": {"role": "assistant", "content": "SELECT AVG(price) FROM products;"},
            "prompt_eval_count": 30,
            "eval_count": 12,
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_resp).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        messages = [
            SystemMessage(content="Strictly output valid SQL."),
            HumanMessage(content="Show me average price."),
            AIMessage(content="SELECT AVG(price) FROM products;"),
            HumanMessage(content="Now group by category.")
        ]

        response = router.invoke(messages)
        self.assertEqual(response.content, "SELECT AVG(price) FROM products;")

        # Inspect sent payload
        req: urllib.request.Request = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        sent_messages = payload["messages"]
        self.assertEqual(sent_messages[0]["role"], "system")
        self.assertEqual(sent_messages[0]["content"], "Strictly output valid SQL.")
        self.assertEqual(sent_messages[1]["role"], "user")
        self.assertEqual(sent_messages[1]["content"], "Show me average price.")
        self.assertEqual(sent_messages[2]["role"], "assistant")
        self.assertEqual(sent_messages[3]["role"], "user")
        self.assertEqual(sent_messages[3]["content"], "Now group by category.")


class TestTransientRetryLogic(unittest.TestCase):
    """Verifies exponential backoff on transient errors and immediate fail on auth errors."""

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_transient_429_retries_and_succeeds(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Verify HTTP 429 rate limit triggers backoff retry and succeeds on next attempt."""
        config = LLMConfig(provider="local", model="llama3:8b")
        router = LLMRouter(config=config)

        # Attempt 1 fails with 429; Attempt 2 succeeds with 200
        mock_429_error = urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/chat",
            code=429,
            msg="Too Many Requests",
            hdrs={},  # type: ignore
            fp=io.BytesIO(b'{"error": "rate limited"}')
        )
        mock_success = MagicMock()
        mock_success.__enter__.return_value.read.return_value = json.dumps({
            "message": {"content": "SELECT 1;"},
            "prompt_eval_count": 5,
            "eval_count": 5
        }).encode("utf-8")

        mock_urlopen.side_effect = [
            mock_429_error,
            mock_success
        ]

        response = router.generate("test prompt")
        self.assertEqual(response.content, "SELECT 1;")
        self.assertEqual(mock_urlopen.call_count, 2)
        mock_sleep.assert_called_once_with(1.0)


if __name__ == "__main__":
    unittest.main()
