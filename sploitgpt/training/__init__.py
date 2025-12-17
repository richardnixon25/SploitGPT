"""
SploitGPT Training Module

Handles:
- Install-time fine-tuning with LoRA
- Session data collection for continuous learning
- Model export and optimization
"""

from .collector import SessionCollector

__all__ = ["run_finetuning", "check_gpu_available", "SessionCollector"]


def run_finetuning(*args, **kwargs):  # pragma: no cover - thin wrapper
    from .finetune import run_finetuning as _run

    return _run(*args, **kwargs)


def check_gpu_available(*args, **kwargs):  # pragma: no cover - thin wrapper
    from .finetune import check_gpu_available as _chk

    return _chk(*args, **kwargs)
