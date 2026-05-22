"""Runtime configuration for the active memory leak control plane."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"

# LLM Provider Configuration
# Options: "claude", "local", "openai", "openai_compatible", or "auto"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto")

# Claude API Configuration
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

# Local LLM Configuration (OpenAI-compatible endpoint)
LOCAL_LLM_BASE_URL = os.getenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "")
LOCAL_LLM_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "not-needed")  # Some local servers require a dummy key

# Clang configuration
CLANG_PATH = os.getenv("CLANG_PATH", "clang")

# Analysis settings
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "4096"))
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.0"))  # Deterministic for reproducibility (touched to trigger reload)
