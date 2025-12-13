"""
Model Configuration Module
Centralized registry for available LLM models used in vulnerability scanning and exploit generation.

Environment overrides (per-model):
  MODEL_BASE_PATH_<MODEL_ID>=/path/to/model
  MODEL_ADAPTER_PATH_<MODEL_ID>=adapter_dir_or_path
Global defaults:
  MODEL_BASE_PATH_DEFAULT=/path/to/default/model
  MODEL_BASE_DIR=/base/dir/for/relative/paths
  ADAPTER_BASE_DIR=/base/dir/for/adapters
"""

import os

# Base directory for saved models (adapters)
BASE_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
SAVED_MODELS_DIR = os.path.join(BASE_MODEL_DIR, "saved_models")
MODEL_BASE_DIR = os.getenv("MODEL_BASE_DIR")  # e.g., /app/models mounted via Docker
ADAPTER_BASE_DIR = os.getenv("ADAPTER_BASE_DIR")  # optional separate adapter mount

# Model Registry
# Each entry contains:
# - name: Display name for UI
# - base_path: Path to the base model weights
# - adapter_path: Relative path to LoRA adapter (inside saved_models), or None
# - type: Model architecture type
MODEL_REGISTRY = {
    "hermes": {
        "name": "Hermes 3 8B",
        "base_path": r"E:\GRAND_AI_MODELS\hermes-3-llama-3.1-8b",
        "adapter_path": "hermes_adapter",  # Fine-tuned adapter
        "type": "causal_lm"
    },
    "qwen": {
        "name": "Qwen2.5-VL 7B (Fine-tuned)",
        "base_path": r"E:\GRAND_AI_MODELS\models--huihui-ai--Qwen2.5-VL-7B-Instruct-abliterated\snapshots\fa935a7958b3669b194c7ba4d1cfcebbe222641d",
        "adapter_path": "qwen2.5_vl_adapter",
        "type": "vision_lm",  # NOTE: This is a Vision-Language model
        "text_only": False
    }
}

# Default model to use if none specified
DEFAULT_MODEL = "hermes"

def _resolve_path(path: str, base_dir: str | None) -> str | None:
  """Resolve path with optional base_dir; leave absolute paths untouched."""
  if not path:
    return None
  if os.path.isabs(path):
    return path
  if base_dir:
    return os.path.join(base_dir, path)
  return os.path.join(SAVED_MODELS_DIR, path)


def get_model_config(model_id: str) -> dict:
  """
  Get configuration for a specific model.
    
    Args:
        model_id: Key from MODEL_REGISTRY (e.g., "hermes", "qwen")
        
    Returns:
        dict with model configuration, or default model config if not found
  """
  if model_id not in MODEL_REGISTRY:
    print(f"Warning: Unknown model_id '{model_id}', using default '{DEFAULT_MODEL}'")
    model_id = DEFAULT_MODEL
  
  config = MODEL_REGISTRY[model_id].copy()

  # Allow env overrides for model and adapter paths
  base_override = os.getenv(f"MODEL_BASE_PATH_{model_id.upper()}") or os.getenv("MODEL_BASE_PATH_DEFAULT")
  adapter_override = os.getenv(f"MODEL_ADAPTER_PATH_{model_id.upper()}")
  if base_override:
    config["base_path"] = base_override
  if adapter_override is not None:
    config["adapter_path"] = adapter_override
  
  # Resolve paths (absolute passthrough, otherwise join with supplied base dirs)
  config["base_path"] = _resolve_path(config["base_path"], MODEL_BASE_DIR)
  adapter_base = ADAPTER_BASE_DIR or MODEL_BASE_DIR
  config["adapter_path_full"] = _resolve_path(config.get("adapter_path"), adapter_base)
  
  return config


def get_available_models() -> list:
    """
    Get list of available models for UI dropdowns.
    
    Returns:
        List of tuples: [(model_id, display_name), ...]
    """
    return [(k, v["name"]) for k, v in MODEL_REGISTRY.items()]


def validate_model_paths(model_id: str) -> dict:
  """
  Validate that model paths exist.
  
  Returns:
      dict with validation results
  """
  config = get_model_config(model_id)
  results = {
    "model_id": model_id,
    "base_path_exists": os.path.exists(config["base_path"]),
    "adapter_path_exists": config["adapter_path_full"] is None or os.path.exists(config["adapter_path_full"]),
  }
  results["valid"] = results["base_path_exists"] and results["adapter_path_exists"]
  return results
