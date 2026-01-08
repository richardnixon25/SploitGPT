# Sliver Training Data

This directory contains training data for extending SploitGPT to support Sliver C2.

## Directory Structure

```
sliver/
├── raw/                    # Raw scraped/collected data
│   ├── docs/              # Official documentation
│   ├── wiki/              # GitHub wiki content
│   ├── armory/            # Armory extension docs
│   └── examples/          # Real-world examples
│
├── processed/              # Cleaned, structured data
│   ├── commands/          # Command reference pairs
│   ├── scenarios/         # Attack scenario datasets
│   ├── conversations/     # Multi-turn dialogues
│   └── explanations/      # Educational content
│
├── synthetic/              # Generated/augmented data
│   ├── command_variations/
│   ├── error_handling/
│   └── tactical_decisions/
│
├── scripts/                # Processing scripts
├── templates/              # Prompt templates
└── config/                 # Configuration files
```

## Data Format

All processed data should be in JSONL format (one JSON object per line).

### Instruction Format (Alpaca-style)
```json
{"instruction": "How do I...", "input": "", "output": "To do X..."}
```

### Conversation Format (ShareGPT-style)
```json
{"conversations": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
```

## Quality Guidelines

1. **Verify all commands** against Sliver v1.6.x
2. **Include context** - explain WHY, not just WHAT
3. **Be accurate** - test commands before documenting
4. **Stay current** - no deprecated features
5. **Be educational** - this is for learning

## Getting Started

1. Run `scripts/scrape_docs.py` to collect raw documentation
2. Run `scripts/parse_wiki.py` to process wiki content
3. Run `scripts/generate_conversations.py` to create training pairs
4. Run `scripts/validate_data.py` to check quality
5. Run `scripts/export_dataset.py` to create final dataset

See `docs/SLIVER_LLM_TRAINING.md` for complete instructions.
