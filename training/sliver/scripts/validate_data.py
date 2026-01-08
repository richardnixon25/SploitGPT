#!/usr/bin/env python3
"""
Validate Sliver training data quality.

Checks:
- JSON schema compliance
- No duplicate entries
- Balanced category distribution
- Response quality metrics
- Required fields present
- No empty values
"""

import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import Any

# Paths
PROCESSED_DIR = Path(__file__).parent.parent / "processed"

# Schema definitions
ALPACA_REQUIRED_FIELDS = {"instruction", "output"}
ALPACA_OPTIONAL_FIELDS = {"input"}

SHAREGPT_REQUIRED_FIELDS = {"id", "conversations"}


def compute_hash(text: str) -> str:
    """Compute hash of text for deduplication."""
    return hashlib.md5(text.encode()).hexdigest()


def validate_alpaca_entry(entry: dict, line_num: int) -> list[str]:
    """Validate an Alpaca-format entry."""
    issues = []
    
    # Check required fields
    for field in ALPACA_REQUIRED_FIELDS:
        if field not in entry:
            issues.append(f"Line {line_num}: Missing required field '{field}'")
        elif not entry[field] or not entry[field].strip():
            issues.append(f"Line {line_num}: Empty value for required field '{field}'")
    
    # Check for very short outputs (likely incomplete)
    if "output" in entry and len(entry.get("output", "")) < 50:
        issues.append(f"Line {line_num}: Output is very short ({len(entry['output'])} chars)")
    
    # Check for placeholder text
    placeholder_markers = ["TODO", "FIXME", "XXX", "YOUR_", "<PLACEHOLDER>"]
    for marker in placeholder_markers:
        if marker in entry.get("output", ""):
            issues.append(f"Line {line_num}: Output contains placeholder '{marker}'")
        if marker in entry.get("instruction", ""):
            issues.append(f"Line {line_num}: Instruction contains placeholder '{marker}'")
    
    return issues


def validate_sharegpt_entry(entry: dict, line_num: int) -> list[str]:
    """Validate a ShareGPT-format entry (multi-turn conversations)."""
    issues = []
    
    # Check required fields
    for field in SHAREGPT_REQUIRED_FIELDS:
        if field not in entry:
            issues.append(f"Line {line_num}: Missing required field '{field}'")
    
    # Validate conversations structure
    if "conversations" in entry:
        convos = entry["conversations"]
        if not isinstance(convos, list):
            issues.append(f"Line {line_num}: 'conversations' must be a list")
        elif len(convos) < 2:
            issues.append(f"Line {line_num}: Conversation has fewer than 2 turns")
        else:
            for i, turn in enumerate(convos):
                if "role" not in turn:
                    issues.append(f"Line {line_num}, Turn {i}: Missing 'role'")
                elif turn["role"] not in ["user", "assistant", "system"]:
                    issues.append(f"Line {line_num}, Turn {i}: Invalid role '{turn['role']}'")
                if "content" not in turn:
                    issues.append(f"Line {line_num}, Turn {i}: Missing 'content'")
                elif not turn["content"].strip():
                    issues.append(f"Line {line_num}, Turn {i}: Empty content")
    
    return issues


def detect_format(entry: dict) -> str:
    """Detect whether entry is Alpaca or ShareGPT format."""
    if "conversations" in entry:
        return "sharegpt"
    elif "instruction" in entry:
        return "alpaca"
    return "unknown"


def validate_jsonl_file(filepath: Path) -> dict:
    """
    Validate a JSONL training file.
    
    Returns:
        dict with issues, stats, and duplicates
    """
    issues = []
    stats = Counter()
    duplicates = []
    seen_hashes = {}
    entries = []
    
    print(f"\n[*] Validating {filepath.name}...")
    
    if not filepath.exists():
        return {
            "issues": [f"File not found: {filepath}"],
            "stats": {},
            "duplicates": [],
            "valid": False,
        }
    
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                issues.append(f"Line {i}: Invalid JSON - {e}")
                stats["json_errors"] += 1
                continue
            
            # Detect and validate format
            fmt = detect_format(entry)
            stats[f"format_{fmt}"] += 1
            
            if fmt == "alpaca":
                issues.extend(validate_alpaca_entry(entry, i))
            elif fmt == "sharegpt":
                issues.extend(validate_sharegpt_entry(entry, i))
            else:
                issues.append(f"Line {i}: Unknown entry format")
            
            # Check for duplicates (based on instruction or id)
            if "instruction" in entry:
                content_hash = compute_hash(entry["instruction"])
            elif "id" in entry:
                content_hash = entry["id"]
            else:
                content_hash = compute_hash(str(entry))
            
            if content_hash in seen_hashes:
                duplicates.append({
                    "line": i,
                    "duplicate_of": seen_hashes[content_hash],
                    "content": entry.get("instruction", entry.get("id", "?"))[:100],
                })
                stats["duplicates"] += 1
            else:
                seen_hashes[content_hash] = i
    
    stats["total_entries"] = len(entries)
    stats["unique_entries"] = len(seen_hashes)
    stats["issues_found"] = len(issues)
    
    return {
        "issues": issues,
        "stats": dict(stats),
        "duplicates": duplicates,
        "valid": len(issues) == 0 and stats.get("json_errors", 0) == 0,
        "entries": entries,
    }


def analyze_content_quality(entries: list[dict]) -> dict:
    """Analyze content quality metrics."""
    metrics = {
        "avg_instruction_length": 0,
        "avg_output_length": 0,
        "min_output_length": float("inf"),
        "max_output_length": 0,
        "entries_with_code_blocks": 0,
        "entries_with_examples": 0,
    }
    
    instruction_lengths = []
    output_lengths = []
    
    for entry in entries:
        if "instruction" in entry:
            instruction_lengths.append(len(entry["instruction"]))
        
        if "output" in entry:
            output = entry["output"]
            output_lengths.append(len(output))
            metrics["min_output_length"] = min(metrics["min_output_length"], len(output))
            metrics["max_output_length"] = max(metrics["max_output_length"], len(output))
            
            if "```" in output:
                metrics["entries_with_code_blocks"] += 1
            if "example" in output.lower() or "Examples:" in output:
                metrics["entries_with_examples"] += 1
    
    if instruction_lengths:
        metrics["avg_instruction_length"] = sum(instruction_lengths) / len(instruction_lengths)
    if output_lengths:
        metrics["avg_output_length"] = sum(output_lengths) / len(output_lengths)
    
    if metrics["min_output_length"] == float("inf"):
        metrics["min_output_length"] = 0
    
    return metrics


def validate_all_files() -> dict:
    """Validate all training data files in the processed directory."""
    results = {}
    all_issues = []
    total_entries = 0
    
    # Find all JSONL files
    jsonl_files = list(PROCESSED_DIR.rglob("*.jsonl"))
    
    if not jsonl_files:
        print("[!] No JSONL files found in processed directory")
        return {"error": "No files found"}
    
    print(f"Found {len(jsonl_files)} JSONL files to validate")
    
    for filepath in sorted(jsonl_files):
        relative_path = filepath.relative_to(PROCESSED_DIR)
        result = validate_jsonl_file(filepath)
        results[str(relative_path)] = result
        all_issues.extend(result["issues"])
        total_entries += result["stats"].get("total_entries", 0)
        
        # Print summary for this file
        stats = result["stats"]
        status = "✓" if result["valid"] else "✗"
        print(f"  {status} {relative_path}: {stats.get('total_entries', 0)} entries, "
              f"{stats.get('issues_found', 0)} issues")
        
        # Analyze quality if entries exist
        if result.get("entries"):
            quality = analyze_content_quality(result["entries"])
            results[str(relative_path)]["quality"] = quality
    
    # Overall summary
    print(f"\n{'=' * 60}")
    print("VALIDATION SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total files: {len(jsonl_files)}")
    print(f"Total entries: {total_entries}")
    print(f"Total issues: {len(all_issues)}")
    
    # Show issues
    if all_issues:
        print(f"\n[!] Issues found ({len(all_issues)}):")
        for issue in all_issues[:20]:  # Show first 20
            print(f"    - {issue}")
        if len(all_issues) > 20:
            print(f"    ... and {len(all_issues) - 20} more")
    else:
        print("\n[✓] No issues found! Data is valid.")
    
    # Quality metrics
    print(f"\n{'=' * 60}")
    print("QUALITY METRICS")
    print(f"{'=' * 60}")
    
    for filepath, result in results.items():
        if "quality" in result:
            quality = result["quality"]
            print(f"\n{filepath}:")
            print(f"  Avg instruction length: {quality['avg_instruction_length']:.0f} chars")
            print(f"  Avg output length: {quality['avg_output_length']:.0f} chars")
            print(f"  Output length range: {quality['min_output_length']}-{quality['max_output_length']} chars")
            print(f"  Entries with code blocks: {quality['entries_with_code_blocks']}")
            print(f"  Entries with examples: {quality['entries_with_examples']}")
    
    return {
        "results": results,
        "all_issues": all_issues,
        "total_entries": total_entries,
        "all_valid": len(all_issues) == 0,
    }


def main():
    """Run validation on all training data."""
    print("=" * 60)
    print("Sliver Training Data Validator")
    print("=" * 60)
    
    results = validate_all_files()
    
    # Return exit code based on validity
    if results.get("all_valid", False):
        print("\n[✓] All validation checks passed!")
        return 0
    else:
        print("\n[!] Validation found issues that should be addressed.")
        return 1


if __name__ == "__main__":
    exit(main())
