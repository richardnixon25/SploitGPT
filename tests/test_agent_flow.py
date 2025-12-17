"""Agent interaction flow tests.

These focus on the ask_user/confirm gating logic to ensure the agent
pauses for user input and resumes correctly without hitting real tools
or LLM endpoints.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sploitgpt.agent.agent import Agent
from sploitgpt.core.boot import BootContext


def _stub_settings(tmp_path):
    """Create a minimal settings stub with isolated paths."""
    settings = SimpleNamespace(
        sessions_dir=tmp_path / "sessions",
        data_dir=tmp_path / "data",
        loot_dir=tmp_path / "loot",
        effective_model="test-model",
        ollama_host="http://localhost:11434",
    )
    settings.sessions_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.loot_dir.mkdir(parents=True, exist_ok=True)
    return settings


@pytest.mark.asyncio
async def test_agent_emits_choice_for_ask_user(monkeypatch, tmp_path):
    """Agent should surface ask_user tool calls as a choice."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    ask_user_response = {
        "message": {
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "ask_user",
                        "arguments": {
                            "question": "Pick a path?",
                            "options": ["A", "B"],
                        },
                    }
                }
            ],
        }
    }

    monkeypatch.setattr(agent, "_call_llm", AsyncMock(return_value=ask_user_response))

    outputs = [r async for r in agent.process("enumerate 1.2.3.4")]

    assert any(r.type == "choice" for r in outputs)
    assert agent._pending is not None
    assert agent._pending.kind == "ask_user"


@pytest.mark.asyncio
async def test_agent_confirm_and_executes_tool(monkeypatch, tmp_path):
    """Agent should pause for confirmation, execute, then finish."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # LLM responses in order: initial tool call, then finish.
    responses = [
        {
            "message": {
                "content": "Running scan",
                "tool_calls": [
                    {
                        "function": {
                            "name": "terminal",
                            "arguments": {"command": "echo hi"},
                        }
                    }
                ],
            }
        },
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish",
                            "arguments": {"summary": "done", "techniques_used": ["T0000"]},
                        }
                    }
                ],
            }
        },
    ]

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    first_outputs = [r async for r in agent.process("scan 10.0.0.1")]
    assert any(r.type == "choice" for r in first_outputs)

    follow_up = [r async for r in agent.submit_choice("1")]

    assert any(r.type == "command" for r in follow_up)
    assert any(r.type == "result" for r in follow_up)
    assert any(r.type == "done" for r in follow_up)
