"""
SploitGPT Training Module

Handles:
- Install-time fine-tuning with LoRA
- Session data collection for continuous learning
- Model export and optimization
"""

from .finetune import run_finetuning, check_gpu_available
from .collector import SessionCollector

__all__ = ["run_finetuning", "check_gpu_available", "SessionCollector"]
