import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import logging

logging.basicConfig(level=logging.INFO)

class VulnerabilityScanner:
    def __init__(self, model_name="microsoft/codebert-base", num_labels=2, model_path=None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        if model_path:
            logging.info(f"Loading fine-tuned model from {model_path}")
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        else:
            logging.info(f"Loading base model {model_name}")
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=num_labels)
            
        self.model.to(self.device)
        self.model.eval()

    def scan(self, code_snippet):
        """
        Scans a code snippet for vulnerabilities.
        Returns:
            dict: {'is_vulnerable': bool, 'confidence': float}
        """
        inputs = self.tokenizer(code_snippet, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        vulnerable_prob = probs[0][1].item()
        is_vulnerable = vulnerable_prob > 0.5
        
        return {
            "is_vulnerable": is_vulnerable,
            "confidence": vulnerable_prob
        }

if __name__ == "__main__":
    # Simple test
    scanner = VulnerabilityScanner()
    sample_code = "int main() { return 0; }"
    result = scanner.scan(sample_code)
    print(f"Scan result: {result}")
