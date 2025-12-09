"""
SploitGPT Configuration
"""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment."""
    
    # Ollama / LLM settings
    ollama_host: str = "http://localhost:11434"
    model: str = "qwen2.5:32b"
    llm_model: str = "ollama/qwen2.5:32b"
    
    # Metasploit RPC
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "sploitgpt"
    msf_ssl: bool = False
    
    # Paths
    loot_dir: Path = Path("/app/loot")
    sessions_dir: Path = Path("/app/sessions")
    data_dir: Path = Path("/app/data")
    
    # Behavior
    auto_train: bool = True  # Train on new session data at boot
    ask_threshold: float = 0.7  # Confidence below this triggers clarifying question
    max_retries: int = 3
    command_timeout: int = 300  # 5 minutes
    
    # Debug
    debug: bool = False
    log_level: str = "INFO"
    
    class Config:
        env_prefix = "SPLOITGPT_"
        env_file = ".env"
        extra = "ignore"


def get_settings() -> Settings:
    """Get application settings."""
    return Settings()


# Create directories on import
settings = get_settings()
settings.loot_dir.mkdir(parents=True, exist_ok=True)
settings.sessions_dir.mkdir(parents=True, exist_ok=True)
settings.data_dir.mkdir(parents=True, exist_ok=True)
