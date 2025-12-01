import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import logging

logging.basicConfig(level=logging.INFO)

class PatchGenerator:
    def __init__(self, model_name="Salesforce/codet5-base", model_path=None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        if model_path:
            logging.info(f"Loading fine-tuned patch model from {model_path}")
            self.model = AutoModelForSeq2SeqLM.from_pretrained(model_path)
        else:
            logging.info(f"Loading base model {model_name}")
            self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
            
        self.model.to(self.device)
        self.model.eval()

    def generate_patch(self, vulnerable_code, max_length=128):
        """
        Generates a patch for the given vulnerable code.
        """
        # Prepare input: CodeT5 expects specific formatting or just the code depending on training
        # For base model, we can try prompting or just passing the code
        input_text = vulnerable_code
        
        inputs = self.tokenizer(input_text, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_length=max_length, 
                num_beams=5, 
                early_stopping=True
            )
            
        patch = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return patch

if __name__ == "__main__":
    # Simple test
    generator = PatchGenerator()
    # Example vulnerable code (buffer overflow)
    vuln_code = "void func() { char buf[10]; strcpy(buf, input); }"
    patch = generator.generate_patch(vuln_code)
    print(f"Generated Patch: {patch}")
