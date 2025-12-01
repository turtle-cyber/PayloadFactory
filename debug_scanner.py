import os
import sys
import logging
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "ml_engine")))
from ml_engine.vuln_scanner import VulnScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_comment_removal():
    logger.info("--- Testing Comment Removal ---")
    scanner = VulnScanner(mode="c_cpp")
    
    sample_code = """
    /* License Header */
    // This is a comment
    int main() {
        char *s = "http://example.com"; // String literal
        // Another comment
        return 0;
    }
    """
    
    clean_code = scanner._remove_comments(sample_code)
    logger.info(f"Original:\n{sample_code}")
    logger.info(f"Cleaned:\n{clean_code}")
    
    if "License Header" in clean_code or "This is a comment" in clean_code:
        logger.error("FAILED: Comments not removed.")
    elif "http://example.com" not in clean_code:
        logger.error("FAILED: String literal removed.")
    else:
        logger.info("SUCCESS: Comments removed correctly.")

def test_detection_score():
    logger.info("\n--- Testing Detection Score ---")
    scanner = VulnScanner(mode="c_cpp")
    
    # A simple safe file
    safe_code = """
    int add(int a, int b) {
        return a + b;
    }
    """
    
    logger.info("Scanning Safe Code...")
    vulns = scanner.scan_code(safe_code, file_extension=".c")
    logger.info(f"Findings: {vulns}")
    
    # A simple vulnerable file
    vuln_code = """
    void func(char *input) {
        char buf[10];
        strcpy(buf, input);
    }
    """
    logger.info("Scanning Vulnerable Code...")
    vulns_vuln = scanner.scan_code(vuln_code, file_extension=".c")
    logger.info(f"Findings: {vulns_vuln}")

    with open("debug_results.txt", "w") as f:
        f.write("SAFE CODE FINDINGS:\n")
        f.write(str(vulns) + "\n\n")
        f.write("VULNERABLE CODE FINDINGS:\n")
        f.write(str(vulns_vuln) + "\n")

def test_llm_loading():
    logger.info("\n--- Testing LLM Loading ---")
    try:
        model_path = r"E:\GRAND_AI_MODELS\hermes-3-llama-3.1-8b"
        logger.info(f"Loading Hermes 3 from {model_path}...")
        
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            quantization_config=quantization_config,
            device_map="auto"
        )
        logger.info("SUCCESS: LLM Loaded.")
    except Exception as e:
        logger.error(f"FAILED: LLM Loading crashed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_comment_removal()
    test_detection_score()
    test_llm_loading()
