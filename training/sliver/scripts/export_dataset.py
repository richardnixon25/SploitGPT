#!/usr/bin/env python3
"""
Export Script for Sliver Training Data
Merges, converts, and exports training data for model fine-tuning.

Supports multiple output formats:
- alpaca: Standard instruction/input/output format
- sharegpt: Multi-turn conversation format
- messages: OpenAI-style messages format (compatible with existing MSF data)
"""

import json
import random
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import argparse

# Paths
SLIVER_PROCESSED_DIR = Path(__file__).parent.parent / "processed"
SLIVER_OUTPUT_DIR = Path(__file__).parent.parent / "output"
EXISTING_TRAINING_DIR = Path(__file__).parent.parent.parent.parent / "data" / "training"


@dataclass
class DatasetConfig:
    """Configuration for dataset export."""

    # Category distribution targets (percentage)
    command_reference: float = 0.35
    tactical_scenarios: float = 0.20
    concepts: float = 0.10
    error_handling: float = 0.10
    tool_calls: float = 0.15  # SploitGPT tool integration examples
    attack_chains: float = 0.10  # Multi-turn attack workflows

    # Output settings
    min_entries: int = 1000
    shuffle: bool = True
    seed: int = 42
    include_msf: bool = False
    output_format: str = "alpaca"  # alpaca, sharegpt, messages


class SliverSystemPrompt:
    """System prompts for different contexts."""

    GENERAL = """You are SploitGPT, an autonomous penetration testing assistant with expertise in Sliver C2 framework. You help operators effectively use Sliver for authorized security assessments.

When asked about Sliver commands:
- Provide accurate syntax and examples
- Explain operational context and when to use the command
- Suggest OPSEC considerations when relevant

For tactical questions:
- Break down complex operations into clear steps
- Consider detection risks and recommend evasion techniques
- Provide alternative approaches when appropriate"""

    SLIVER_OPERATOR = """You are an expert Sliver C2 operator assistant. You provide detailed guidance on:
- Implant generation and deployment
- Listener configuration (mTLS, HTTPS, DNS, WireGuard)
- Post-exploitation and lateral movement
- Credential harvesting and privilege escalation
- Pivoting and tunneling
- Operational security and EDR evasion

Always consider the tactical context and provide actionable, safe guidance for authorized penetration testing."""


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Load JSONL file."""
    entries = []
    if path.exists():
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    return entries


def save_jsonl(entries: List[Dict[str, Any]], path: Path):
    """Save entries to JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"  Saved {len(entries)} entries to {path}")


def deduplicate_entries(entries: List[Dict[str, Any]], key_func) -> List[Dict[str, Any]]:
    """Remove duplicates based on key function."""
    seen = set()
    unique = []
    for entry in entries:
        key = key_func(entry)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def alpaca_to_messages(entry: Dict[str, Any], system_prompt: str = None) -> Dict[str, Any]:
    """Convert Alpaca format to messages format."""
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    # User message
    user_content = entry.get("instruction", "")
    if entry.get("input"):
        user_content = f"{user_content}\n\n{entry['input']}"
    messages.append({"role": "user", "content": user_content})

    # Assistant message
    messages.append({"role": "assistant", "content": entry.get("output", "")})

    return {"messages": messages}


def normalize_sharegpt(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize ShareGPT format (handle both from/value and role/content)."""
    conversations = entry.get("conversations", [])
    normalized = []

    for turn in conversations:
        # Handle 'from'/'value' format (common in training data)
        if "from" in turn:
            from_val = turn.get("from", "human")
            role = "user" if from_val in ("human", "user") else "assistant"
            content = turn.get("value", "")
        # Handle 'role'/'content' format
        else:
            role = turn.get("role", "user")
            content = turn.get("content", "")

        normalized.append({"role": role, "content": content})

    return {"conversations": normalized}


def sharegpt_to_messages(entry: Dict[str, Any], system_prompt: str = None) -> Dict[str, Any]:
    """Convert ShareGPT format to messages format."""
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    # Normalize first to handle both from/value and role/content formats
    normalized = normalize_sharegpt(entry)

    for turn in normalized.get("conversations", []):
        role = turn.get("role", "user")
        content = turn.get("content", "")
        messages.append({"role": role, "content": content})

    return {"messages": messages}


def messages_to_alpaca(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert messages format to Alpaca format (may produce multiple entries)."""
    messages = entry.get("messages", [])
    alpaca_entries = []

    # Extract user/assistant pairs
    i = 0
    while i < len(messages):
        msg = messages[i]
        if msg.get("role") == "user":
            # Find the next assistant response
            for j in range(i + 1, len(messages)):
                if messages[j].get("role") == "assistant":
                    alpaca_entries.append(
                        {
                            "instruction": msg.get("content", ""),
                            "input": "",
                            "output": messages[j].get("content", ""),
                        }
                    )
                    i = j
                    break
        i += 1

    return (
        alpaca_entries
        if alpaca_entries
        else [
            {
                "instruction": messages[1].get("content", "") if len(messages) > 1 else "",
                "input": "",
                "output": messages[2].get("content", "") if len(messages) > 2 else "",
            }
        ]
    )


def messages_to_sharegpt(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Convert messages format to ShareGPT format."""
    messages = entry.get("messages", [])
    conversations = []

    for msg in messages:
        if msg.get("role") != "system":
            conversations.append(
                {"role": msg.get("role", "user"), "content": msg.get("content", "")}
            )

    return {"conversations": conversations}


class DatasetExporter:
    """Export and merge training datasets."""

    def __init__(self, config: DatasetConfig):
        self.config = config
        random.seed(config.seed)

    def load_sliver_data(self, include_scaled: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """Load all Sliver training data including scaled data."""
        data = {
            "command_reference": [],
            "tactical_scenarios": [],
            "concepts": [],
            "error_handling": [],
            "tool_calls": [],
            "attack_chains": [],
        }

        # Load command reference (Alpaca format)
        cmd_path = SLIVER_PROCESSED_DIR / "commands" / "command_reference.jsonl"
        data["command_reference"] = load_jsonl(cmd_path)
        print(f"Loaded {len(data['command_reference'])} command reference entries")

        # Load tactical scenarios (ShareGPT format)
        scenario_path = SLIVER_PROCESSED_DIR / "scenarios" / "tactical_scenarios.jsonl"
        data["tactical_scenarios"] = load_jsonl(scenario_path)
        print(f"Loaded {len(data['tactical_scenarios'])} tactical scenarios")

        # Load concepts (Alpaca format)
        concepts_path = SLIVER_PROCESSED_DIR / "explanations" / "concepts.jsonl"
        data["concepts"] = load_jsonl(concepts_path)
        print(f"Loaded {len(data['concepts'])} concept explanations")

        # Load error handling (Alpaca format)
        errors_path = SLIVER_PROCESSED_DIR / "conversations" / "error_handling.jsonl"
        data["error_handling"] = load_jsonl(errors_path)
        print(f"Loaded {len(data['error_handling'])} error handling entries")

        # Load tool calls - SploitGPT tool integration (Alpaca format)
        tool_calls_path = SLIVER_PROCESSED_DIR / "conversations" / "tool_calls.jsonl"
        data["tool_calls"] = load_jsonl(tool_calls_path)
        print(f"Loaded {len(data['tool_calls'])} tool call examples")

        # Load attack chains - multi-turn workflows (ShareGPT format with from/value)
        attack_chains_path = SLIVER_PROCESSED_DIR / "conversations" / "attack_chains.jsonl"
        data["attack_chains"] = load_jsonl(attack_chains_path)
        print(f"Loaded {len(data['attack_chains'])} attack chain conversations")

        # Load scaled data if available
        if include_scaled:
            scaled_dir = SLIVER_PROCESSED_DIR / "scaled"
            if scaled_dir.exists():
                # Scaled commands
                scaled_cmds = load_jsonl(scaled_dir / "commands_extended.jsonl")
                data["command_reference"].extend(scaled_cmds)
                print(f"  + {len(scaled_cmds)} scaled command entries")

                # Scaled scenarios
                scaled_scenarios = load_jsonl(scaled_dir / "scenarios_extended.jsonl")
                data["tactical_scenarios"].extend(scaled_scenarios)
                print(f"  + {len(scaled_scenarios)} scaled scenario entries")

                # Scaled concepts
                scaled_concepts = load_jsonl(scaled_dir / "concepts_extended.jsonl")
                data["concepts"].extend(scaled_concepts)
                print(f"  + {len(scaled_concepts)} scaled concept entries")

                # Scaled errors
                scaled_errors = load_jsonl(scaled_dir / "errors_extended.jsonl")
                data["error_handling"].extend(scaled_errors)
                print(f"  + {len(scaled_errors)} scaled error entries")

                # Question variations (treat as command reference)
                question_vars = load_jsonl(scaled_dir / "question_variations.jsonl")
                data["command_reference"].extend(question_vars)
                print(f"  + {len(question_vars)} question variation entries")

        return data

    def load_existing_msf_data(self) -> List[Dict[str, Any]]:
        """Load existing MSF training data (messages format)."""
        msf_data = []

        if EXISTING_TRAINING_DIR.exists():
            for jsonl_file in EXISTING_TRAINING_DIR.glob("*.jsonl"):
                entries = load_jsonl(jsonl_file)
                msf_data.extend(entries)
                print(f"Loaded {len(entries)} entries from {jsonl_file.name}")

        return msf_data

    def convert_to_format(
        self,
        entry: Dict[str, Any],
        source_format: str,
        target_format: str,
        system_prompt: str = None,
    ) -> List[Dict[str, Any]]:
        """Convert entry between formats."""
        if source_format == target_format:
            return [entry]

        # Alpaca -> other formats
        if source_format == "alpaca":
            if target_format == "messages":
                return [alpaca_to_messages(entry, system_prompt)]
            elif target_format == "sharegpt":
                return [
                    {
                        "conversations": [
                            {"role": "user", "content": entry.get("instruction", "")},
                            {"role": "assistant", "content": entry.get("output", "")},
                        ]
                    }
                ]

        # ShareGPT -> other formats
        elif source_format == "sharegpt":
            if target_format == "messages":
                return [sharegpt_to_messages(entry, system_prompt)]
            elif target_format == "alpaca":
                # Convert each turn pair to an alpaca entry
                convs = entry.get("conversations", [])
                alpaca_list = []
                for i in range(0, len(convs) - 1, 2):
                    if convs[i].get("role") == "user" and i + 1 < len(convs):
                        alpaca_list.append(
                            {
                                "instruction": convs[i].get("content", ""),
                                "input": "",
                                "output": convs[i + 1].get("content", ""),
                            }
                        )
                return alpaca_list if alpaca_list else [entry]

        # Messages -> other formats
        elif source_format == "messages":
            if target_format == "alpaca":
                return messages_to_alpaca(entry)
            elif target_format == "sharegpt":
                return [messages_to_sharegpt(entry)]

        return [entry]

    def balance_categories(self, data: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Balance dataset according to target distribution."""
        total_sliver = sum(len(v) for v in data.values())
        target_total = max(self.config.min_entries, total_sliver)

        balanced = []
        category_counts = {}

        # Calculate target counts
        targets = {
            "command_reference": int(target_total * self.config.command_reference),
            "tactical_scenarios": int(target_total * self.config.tactical_scenarios),
            "concepts": int(target_total * self.config.concepts),
            "error_handling": int(target_total * self.config.error_handling),
            "tool_calls": int(target_total * self.config.tool_calls),
            "attack_chains": int(target_total * self.config.attack_chains),
        }

        print(f"\nTarget distribution (total: {target_total}):")
        for cat, target in targets.items():
            available = len(data.get(cat, []))
            actual = min(target, available)
            category_counts[cat] = actual

            # Sample or use all
            entries = data.get(cat, [])
            if len(entries) > target:
                sampled = random.sample(entries, target)
            else:
                sampled = entries
            balanced.extend(sampled)

            print(f"  {cat}: {actual}/{target} (available: {available})")

        return balanced

    def export_sliver_only(self, output_path: Path) -> int:
        """Export Sliver data only."""
        data = self.load_sliver_data()
        target_format = self.config.output_format

        # Convert all data to target format
        converted = []

        # Command reference (Alpaca -> target)
        for entry in data["command_reference"]:
            converted.extend(
                self.convert_to_format(
                    entry, "alpaca", target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
            )

        # Tactical scenarios (ShareGPT -> target)
        for entry in data["tactical_scenarios"]:
            converted.extend(
                self.convert_to_format(
                    entry, "sharegpt", target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
            )

        # Concepts (Alpaca -> target)
        for entry in data["concepts"]:
            converted.extend(
                self.convert_to_format(entry, "alpaca", target_format, SliverSystemPrompt.GENERAL)
            )

        # Error handling (Alpaca -> target)
        for entry in data["error_handling"]:
            converted.extend(
                self.convert_to_format(
                    entry, "alpaca", target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
            )

        # Tool calls - SploitGPT tool integration (Alpaca -> target)
        for entry in data["tool_calls"]:
            converted.extend(
                self.convert_to_format(
                    entry, "alpaca", target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
            )

        # Attack chains - multi-turn workflows (ShareGPT -> target)
        for entry in data["attack_chains"]:
            # Normalize first to handle from/value format
            normalized = normalize_sharegpt(entry)
            converted.extend(
                self.convert_to_format(
                    normalized, "sharegpt", target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
            )

        # Deduplicate
        if target_format == "alpaca":
            key_func = lambda x: hashlib.md5(x.get("instruction", "").encode()).hexdigest()
        else:
            key_func = lambda x: hashlib.md5(json.dumps(x, sort_keys=True).encode()).hexdigest()

        converted = deduplicate_entries(converted, key_func)

        # Shuffle if requested
        if self.config.shuffle:
            random.shuffle(converted)

        # Save
        save_jsonl(converted, output_path)
        return len(converted)

    def export_merged(self, output_path: Path) -> int:
        """Export merged Sliver + MSF data."""
        # Load all data
        sliver_data = self.load_sliver_data()
        msf_data = self.load_existing_msf_data()

        target_format = self.config.output_format
        merged = []

        # Convert Sliver data
        sharegpt_categories = {"tactical_scenarios", "attack_chains"}
        for cat, entries in sliver_data.items():
            source_format = "sharegpt" if cat in sharegpt_categories else "alpaca"
            for entry in entries:
                # Normalize ShareGPT entries to handle from/value format
                if cat in sharegpt_categories:
                    entry = normalize_sharegpt(entry)
                merged.extend(
                    self.convert_to_format(
                        entry, source_format, target_format, SliverSystemPrompt.SLIVER_OPERATOR
                    )
                )

        # Convert MSF data if included
        if self.config.include_msf:
            for entry in msf_data:
                merged.extend(self.convert_to_format(entry, "messages", target_format))

        # Deduplicate
        if target_format == "alpaca":
            key_func = lambda x: hashlib.md5(x.get("instruction", "").encode()).hexdigest()
        elif target_format == "sharegpt":
            key_func = lambda x: hashlib.md5(
                json.dumps(x.get("conversations", []), sort_keys=True).encode()
            ).hexdigest()
        else:
            key_func = lambda x: hashlib.md5(
                json.dumps(x.get("messages", []), sort_keys=True).encode()
            ).hexdigest()

        merged = deduplicate_entries(merged, key_func)

        if self.config.shuffle:
            random.shuffle(merged)

        save_jsonl(merged, output_path)
        return len(merged)

    def export_train_test_split(self, output_dir: Path, test_ratio: float = 0.1) -> Dict[str, int]:
        """Export with train/test split."""
        data = self.load_sliver_data()
        target_format = self.config.output_format

        # Convert all
        sharegpt_categories = {"tactical_scenarios", "attack_chains"}
        all_entries = []
        for cat, entries in data.items():
            source_format = "sharegpt" if cat in sharegpt_categories else "alpaca"
            for entry in entries:
                # Normalize ShareGPT entries to handle from/value format
                if cat in sharegpt_categories:
                    entry = normalize_sharegpt(entry)
                converted = self.convert_to_format(
                    entry, source_format, target_format, SliverSystemPrompt.SLIVER_OPERATOR
                )
                for c in converted:
                    c["_category"] = cat  # Tag for stratified split
                all_entries.extend(converted)

        # Deduplicate
        if target_format == "alpaca":
            key_func = lambda x: hashlib.md5(x.get("instruction", "").encode()).hexdigest()
        else:
            key_func = lambda x: hashlib.md5(json.dumps(x, sort_keys=True).encode()).hexdigest()

        all_entries = deduplicate_entries(all_entries, key_func)

        # Stratified split by category
        by_category = defaultdict(list)
        for entry in all_entries:
            cat = entry.pop("_category", "unknown")
            by_category[cat].append(entry)

        train_entries = []
        test_entries = []

        for cat, entries in by_category.items():
            random.shuffle(entries)
            split_idx = max(1, int(len(entries) * test_ratio))
            test_entries.extend(entries[:split_idx])
            train_entries.extend(entries[split_idx:])

        if self.config.shuffle:
            random.shuffle(train_entries)
            random.shuffle(test_entries)

        # Save
        output_dir.mkdir(parents=True, exist_ok=True)
        save_jsonl(train_entries, output_dir / "train.jsonl")
        save_jsonl(test_entries, output_dir / "test.jsonl")

        return {
            "train": len(train_entries),
            "test": len(test_entries),
            "total": len(train_entries) + len(test_entries),
        }

    def generate_statistics(self) -> Dict[str, Any]:
        """Generate dataset statistics."""
        data = self.load_sliver_data()

        stats = {
            "categories": {},
            "total_entries": 0,
            "format_distribution": {},
        }

        for cat, entries in data.items():
            cat_stats = {
                "count": len(entries),
                "avg_instruction_len": 0,
                "avg_output_len": 0,
            }

            if entries:
                if "instruction" in entries[0]:  # Alpaca format
                    cat_stats["avg_instruction_len"] = sum(
                        len(e.get("instruction", "")) for e in entries
                    ) / len(entries)
                    cat_stats["avg_output_len"] = sum(
                        len(e.get("output", "")) for e in entries
                    ) / len(entries)
                elif "conversations" in entries[0]:  # ShareGPT format
                    total_turns = sum(len(e.get("conversations", [])) for e in entries)
                    cat_stats["avg_turns"] = total_turns / len(entries)

            stats["categories"][cat] = cat_stats
            stats["total_entries"] += len(entries)

        return stats


def main():
    parser = argparse.ArgumentParser(description="Export Sliver training data")
    parser.add_argument(
        "--format",
        choices=["alpaca", "sharegpt", "messages"],
        default="alpaca",
        help="Output format (default: alpaca)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=SLIVER_OUTPUT_DIR / "sliver_training.jsonl",
        help="Output file path",
    )
    parser.add_argument(
        "--include-msf", action="store_true", help="Include existing MSF training data"
    )
    parser.add_argument("--split", action="store_true", help="Create train/test split")
    parser.add_argument(
        "--test-ratio", type=float, default=0.1, help="Test set ratio (default: 0.1)"
    )
    parser.add_argument("--no-shuffle", action="store_true", help="Don't shuffle the output")
    parser.add_argument("--stats", action="store_true", help="Print dataset statistics")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")

    args = parser.parse_args()

    # Configure
    config = DatasetConfig(
        output_format=args.format,
        shuffle=not args.no_shuffle,
        seed=args.seed,
        include_msf=args.include_msf,
    )

    exporter = DatasetExporter(config)

    # Print stats if requested
    if args.stats:
        print("\n" + "=" * 60)
        print("DATASET STATISTICS")
        print("=" * 60)
        stats = exporter.generate_statistics()
        print(f"\nTotal entries: {stats['total_entries']}")
        print("\nBy category:")
        for cat, cat_stats in stats["categories"].items():
            print(f"\n  {cat}:")
            for key, value in cat_stats.items():
                if isinstance(value, float):
                    print(f"    {key}: {value:.1f}")
                else:
                    print(f"    {key}: {value}")
        print("=" * 60 + "\n")

    # Export
    print("\n" + "=" * 60)
    print("EXPORTING DATASET")
    print("=" * 60)
    print(f"Format: {args.format}")
    print(f"Include MSF: {args.include_msf}")

    if args.split:
        output_dir = args.output.parent if args.output.suffix == ".jsonl" else args.output
        result = exporter.export_train_test_split(output_dir, args.test_ratio)
        print(f"\n✓ Exported train/test split:")
        print(f"  Train: {result['train']} entries")
        print(f"  Test: {result['test']} entries")
        print(f"  Total: {result['total']} entries")
    elif args.include_msf:
        count = exporter.export_merged(args.output)
        print(f"\n✓ Exported {count} merged entries to {args.output}")
    else:
        count = exporter.export_sliver_only(args.output)
        print(f"\n✓ Exported {count} Sliver entries to {args.output}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
