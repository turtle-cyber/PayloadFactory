"""
Model Configuration Module
Centralized registry for available LLM models used in vulnerability scanning and exploit generation.
"""

import os

# Base directory for saved models (adapters)
BASE_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
SAVED_MODELS_DIR = os.path.join(BASE_MODEL_DIR, "saved_models")

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
    
    # Resolve adapter path to absolute path if specified
    if config.get("adapter_path"):
        config["adapter_path_full"] = os.path.join(SAVED_MODELS_DIR, config["adapter_path"])
    else:
        config["adapter_path_full"] = None
    
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
