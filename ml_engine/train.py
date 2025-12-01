import torch
import os
import pandas as pd
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from torch.utils.data import Dataset
import logging
import argparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Debug prints
print(f"Torch version: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"Device: {torch.cuda.get_device_name(0)}")
else:
    print("WARNING: CUDA is NOT available. Training will run on CPU.")

class VulnerabilityDataset(Dataset):
    def __init__(self, csv_file, tokenizer, max_length=512):
        self.data = pd.read_csv(csv_file)
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        code = str(self.data.iloc[idx]['code'])
        label = int(self.data.iloc[idx]['label'])
        
        encoding = self.tokenizer(
            code,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

def train(data_dir, output_dir, model_name="microsoft/codebert-base", epochs=3):
    logger.info(f"Loading tokenizer for {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    
    train_path = os.path.join(data_dir, 'train.csv')
    test_path = os.path.join(data_dir, 'test.csv')
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        logger.error("Train/Test data not found.")
        return

    train_dataset = VulnerabilityDataset(train_path, tokenizer)
    test_dataset = VulnerabilityDataset(test_path, tokenizer)
    
    logger.info(f"Loading model {model_name}")
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=4, # Reduced batch size for safety
        per_device_eval_batch_size=8,
        warmup_steps=100,
        weight_decay=0.01,
        logging_dir=os.path.join(output_dir, 'logs'),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
    )
    
    logger.info("Starting training...")
    trainer.train()
    
    logger.info(f"Saving model to {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Vulnerability Detection Model")
    parser.add_argument("--model", type=str, default="microsoft/codebert-base", help="Model name (e.g., microsoft/unixcoder-base)")
    parser.add_argument("--epochs", type=int, default=3, help="Number of epochs")
    parser.add_argument("--data_dir", type=str, default=r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\data", help="Data directory")
    parser.add_argument("--output_dir", type=str, default=r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\saved_model", help="Output directory")
    
    args = parser.parse_args()
    
    # Create output dir if not exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        
    train(args.data_dir, args.output_dir, args.model, args.epochs)
