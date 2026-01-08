#!/usr/bin/env python3
"""
Expand question variations and clean up training data.

Tasks:
1. Generate 200+ question variations for Sliver commands
2. Deduplicate all JSONL files
3. Create dataset metadata
"""

import json
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Set

# Import knowledge base
from sliver_knowledge_base import SLIVER_COMMANDS, COMMAND_CATEGORIES

# Paths
PROCESSED_DIR = Path(__file__).parent.parent / "processed"
SCALED_DIR = PROCESSED_DIR / "scaled"
OUTPUT_DIR = Path(__file__).parent.parent / "output"
CONFIG_DIR = Path(__file__).parent.parent / "config"

SCALED_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Question Variation Templates
# =============================================================================

# Base templates - {action} is the command description, {cmd} is the command name
QUESTION_TEMPLATES = [
    # Direct how-to questions
    "How do I {action}?",
    "How do I {action} in Sliver?",
    "How can I {action}?",
    "What's the best way to {action}?",
    
    # Syntax-focused
    "What's the syntax for {cmd}?",
    "What's the syntax for the {cmd} command?",
    "Show me the {cmd} syntax",
    "What are the options for {cmd}?",
    "What flags does {cmd} support?",
    
    # Help/show me
    "Can you show me how to {action}?",
    "Show me how to {action}",
    "Help me {action}",
    "I need help with {action}",
    "Explain how to {action}",
    
    # Need/want style
    "I need to {action}. What command?",
    "I need to {action}, what should I use?",
    "I want to {action}. How?",
    "I'm trying to {action}",
    
    # Direct command questions
    "What does {cmd} do?",
    "What is the {cmd} command for?",
    "When should I use {cmd}?",
    "How do I use {cmd}?",
    "What's {cmd} used for?",
    
    # Example requests
    "Give me an example of {cmd}",
    "Show me an example of using {cmd}",
    "Can you give me a {cmd} example?",
    
    # Quick/casual style
    "{cmd} command help",
    "{cmd} usage?",
    "Quick: how to {action}?",
    "{action} - command?",
]

# Category-specific templates
CATEGORY_TEMPLATES = {
    "listener": [
        "How do I start a {cmd} listener?",
        "Set up {cmd} listener",
        "Configure {cmd} C2",
        "Start {cmd} on port 443",
    ],
    "implant": [
        "Generate a {cmd} implant",
        "Create payload with {cmd}",
        "How do I build an implant?",
        "Payload generation with {cmd}",
    ],
    "credential": [
        "Dump credentials with {cmd}",
        "Extract hashes using {cmd}",
        "How do I {action} from the target?",
    ],
    "pivot": [
        "Set up {cmd} for pivoting",
        "Create tunnel with {cmd}",
        "How do I pivot using {cmd}?",
    ],
    "file": [
        "How do I {action} on the target?",
        "{cmd} a file on remote host",
    ],
    "process": [
        "How do I {action} on the target system?",
        "{cmd} process operations",
    ],
}


def generate_question_variations() -> List[Dict[str, Any]]:
    """Generate question variations for all commands."""
    variations = []
    
    for cmd_name, cmd_info in SLIVER_COMMANDS.items():
        action = cmd_info["description"].lower()
        category = cmd_info["category"]
        
        # Generate from base templates
        for template in QUESTION_TEMPLATES:
            try:
                question = template.format(action=action, cmd=cmd_name)
                variations.append(create_alpaca_entry(question, cmd_name, cmd_info))
            except KeyError:
                # Template doesn't use both placeholders, try alternatives
                try:
                    question = template.format(action=action, cmd=cmd_name)
                    variations.append(create_alpaca_entry(question, cmd_name, cmd_info))
                except:
                    pass
        
        # Generate from category-specific templates
        if category in CATEGORY_TEMPLATES:
            for template in CATEGORY_TEMPLATES[category]:
                try:
                    question = template.format(action=action, cmd=cmd_name)
                    variations.append(create_alpaca_entry(question, cmd_name, cmd_info))
                except KeyError:
                    pass
    
    return variations


def create_alpaca_entry(question: str, cmd_name: str, cmd_info: Dict) -> Dict[str, Any]:
    """Create an Alpaca-format training entry."""
    # Shorter response format for variations
    response = f"""Use the `{cmd_name}` command:

```
{cmd_info['syntax']}
```

**Example:**
```
{cmd_info['examples'][0] if cmd_info['examples'] else cmd_name}
```

{cmd_info['explanation'][:300]}..."""
    
    return {
        "instruction": question,
        "input": "",
        "output": response,
    }


# =============================================================================
# Deduplication
# =============================================================================

def load_all_jsonl_files() -> Dict[str, List[Dict]]:
    """Load all JSONL files from processed directory."""
    all_files = {}
    
    for jsonl_file in PROCESSED_DIR.rglob("*.jsonl"):
        rel_path = jsonl_file.relative_to(PROCESSED_DIR)
        entries = []
        with open(jsonl_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        all_files[str(rel_path)] = entries
    
    return all_files


def get_entry_hash(entry: Dict) -> str:
    """Generate a hash for an entry to detect duplicates."""
    # For Alpaca format
    if "instruction" in entry:
        content = entry.get("instruction", "") + entry.get("output", "")
    # For ShareGPT format
    elif "conversations" in entry:
        content = json.dumps(entry["conversations"], sort_keys=True)
    # For messages format
    elif "messages" in entry:
        content = json.dumps(entry["messages"], sort_keys=True)
    else:
        content = json.dumps(entry, sort_keys=True)
    
    return hashlib.md5(content.encode()).hexdigest()


def deduplicate_files(all_files: Dict[str, List[Dict]]) -> tuple:
    """Deduplicate entries across all files."""
    seen_hashes: Set[str] = set()
    duplicates = defaultdict(list)  # hash -> list of (file, entry)
    deduped_files = {}
    
    stats = {
        "total_before": 0,
        "total_after": 0,
        "duplicates_found": 0,
        "files_processed": 0,
    }
    
    for filepath, entries in all_files.items():
        stats["files_processed"] += 1
        stats["total_before"] += len(entries)
        
        unique_entries = []
        for entry in entries:
            entry_hash = get_entry_hash(entry)
            
            if entry_hash not in seen_hashes:
                seen_hashes.add(entry_hash)
                unique_entries.append(entry)
            else:
                duplicates[entry_hash].append((filepath, entry))
                stats["duplicates_found"] += 1
        
        deduped_files[filepath] = unique_entries
        stats["total_after"] += len(unique_entries)
    
    return deduped_files, duplicates, stats


def generate_dedup_report(duplicates: Dict, stats: Dict) -> str:
    """Generate deduplication report."""
    report_lines = [
        "=" * 60,
        "DEDUPLICATION REPORT",
        "=" * 60,
        "",
        f"Files processed: {stats['files_processed']}",
        f"Total entries before: {stats['total_before']}",
        f"Total entries after: {stats['total_after']}",
        f"Duplicates removed: {stats['duplicates_found']}",
        f"Reduction: {stats['duplicates_found'] / max(stats['total_before'], 1) * 100:.1f}%",
        "",
        "-" * 60,
        "DUPLICATE DETAILS",
        "-" * 60,
        "",
    ]
    
    if duplicates:
        # Group duplicates by instruction/content preview
        for entry_hash, locations in list(duplicates.items())[:20]:  # Show first 20
            if locations:
                filepath, entry = locations[0]
                preview = entry.get("instruction", str(entry))[:60]
                report_lines.append(f"  - \"{preview}...\"")
                report_lines.append(f"    Found in: {filepath}")
                report_lines.append("")
    else:
        report_lines.append("  No duplicates found!")
    
    report_lines.extend([
        "",
        "=" * 60,
        "END OF REPORT",
        "=" * 60,
    ])
    
    return "\n".join(report_lines)


# =============================================================================
# Metadata Generation
# =============================================================================

def count_all_entries() -> Dict[str, int]:
    """Count entries in each category."""
    counts = {
        "commands": 0,
        "scenarios": 0,
        "concepts": 0,
        "errors": 0,
        "variations": 0,
    }
    
    # Count from processed files
    for jsonl_file in PROCESSED_DIR.rglob("*.jsonl"):
        with open(jsonl_file, 'r') as f:
            count = sum(1 for line in f if line.strip())
        
        name = jsonl_file.name.lower()
        if "command" in name:
            counts["commands"] += count
        elif "scenario" in name:
            counts["scenarios"] += count
        elif "concept" in name:
            counts["concepts"] += count
        elif "error" in name:
            counts["errors"] += count
        elif "variation" in name:
            counts["variations"] += count
    
    return counts


def create_dataset_metadata(counts: Dict[str, int]) -> Dict[str, Any]:
    """Create dataset metadata JSON."""
    total = sum(counts.values())
    
    return {
        "name": "sploitgpt-sliver",
        "version": "1.0",
        "description": "Sliver C2 training data for SploitGPT",
        "categories": ["commands", "scenarios", "concepts", "errors", "variations"],
        "category_counts": counts,
        "total_examples": total,
        "format": "alpaca",
        "source": "Generated from Sliver v1.6.x documentation and command reference",
        "created": "2026-01-08",
        "files": {
            "train": "output/train.jsonl",
            "test": "output/test.jsonl",
            "full": "output/sliver_training.jsonl",
        }
    }


# =============================================================================
# Main
# =============================================================================

def main():
    print("=" * 60)
    print("Training Data Expansion & Cleanup")
    print("=" * 60)
    
    # Task 1: Generate question variations
    print("\n[Task 1] Generating question variations...")
    variations = generate_question_variations()
    
    # Deduplicate variations
    seen = set()
    unique_variations = []
    for v in variations:
        key = v["instruction"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique_variations.append(v)
    
    # Save variations
    variations_path = SCALED_DIR / "question_variations.jsonl"
    with open(variations_path, 'w') as f:
        for entry in unique_variations:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"  ✓ Generated {len(unique_variations)} unique question variations")
    print(f"    Saved to: {variations_path}")
    
    # Task 2: Deduplicate all files
    print("\n[Task 2] Deduplicating all JSONL files...")
    all_files = load_all_jsonl_files()
    deduped_files, duplicates, stats = deduplicate_files(all_files)
    
    # Generate and save report
    report = generate_dedup_report(duplicates, stats)
    report_path = OUTPUT_DIR / "dedup_report.txt"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"  ✓ Processed {stats['files_processed']} files")
    print(f"  ✓ Found {stats['duplicates_found']} duplicates")
    print(f"  ✓ Report saved to: {report_path}")
    
    # Task 3: Create metadata
    print("\n[Task 3] Creating dataset metadata...")
    counts = count_all_entries()
    metadata = create_dataset_metadata(counts)
    
    metadata_path = CONFIG_DIR / "dataset_info.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"  ✓ Metadata saved to: {metadata_path}")
    print(f"    Total examples: {metadata['total_examples']}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Question variations: {len(unique_variations)}")
    print(f"  Duplicates removed:  {stats['duplicates_found']}")
    print(f"  Total dataset size:  {metadata['total_examples']}")
    print("\nCategory breakdown:")
    for cat, count in counts.items():
        print(f"  - {cat}: {count}")
    print("=" * 60)


if __name__ == "__main__":
    main()
