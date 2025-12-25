#!/usr/bin/env python3
import json
import sys
import time
import urllib.request


API_URL = "http://127.0.0.1:11434/v1/chat/completions"
HEADERS = {"Content-Type": "application/json"}


CASES = [
    ("hello", "plain greeting"),
    ("Who are you?", "identity check"),
    ("Give me a one-sentence recap of what SploitGPT does.", "short recap"),
    ("List three secure coding practices.", "concise bullets"),
    ("Explain SQL injection in one sentence.", "security answer"),
    ("Summarize our conversation so far.", "explicit summary request"),
]


def run_case(prompt: str):
    payload = {
        "model": "sploitgpt-local",
        "messages": [
            {"role": "system", "content": "You are SploitGPT. No JSON, todos, subtasks, or tool calls unless asked."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 200,
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    parsed = json.loads(body)
    return parsed["choices"][0]["message"]["content"].strip()


def check_output(text: str):
    lowered = text.lower()
    errors = []
    if lowered.startswith("{") or lowered.startswith("["):
        errors.append("starts with JSON-like structure")
    if "todo" in lowered or "subtask" in lowered:
        errors.append("mentions todo/subtask")
    if "tool" in lowered and "call" in lowered:
        errors.append("mentions tool call")
    return errors


def main():
    failures = []
    for prompt, label in CASES:
        try:
            start = time.time()
            output = run_case(prompt)
            duration = time.time() - start
            issues = check_output(output)
            status = "OK" if not issues else "FAIL"
            print(f"[{status}] {label} ({duration:.1f}s)")
            print(f"  prompt: {prompt}")
            print(f"  output: {output}")
            if issues:
                print(f"  issues: {', '.join(issues)}")
                failures.append(label)
        except Exception as exc:
            failures.append(label)
            print(f"[ERROR] {label}: {exc}")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
