import os
import torch
import json
import logging
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    Trainer, 
    TrainingArguments,
    EarlyStoppingCallback
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiLangVulnDataset(Dataset):
    def __init__(self, file_path, tokenizer, max_length=512, limit=None):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.data = []
        
        logger.info(f"Loading dataset from {file_path}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                try:
                    item = json.loads(line)
                    code = item.get('code', '')
                    severity = item.get('severity_class')
                    
                    # Label Mapping
                    # None -> 0 (Safe)
                    # LOW/MEDIUM/HIGH/CRITICAL -> 1 (Vulnerable)
                    label = 0 if str(severity) == 'None' else 1
                    
                    if code:
                        self.data.append({'code': code, 'label': label})
                except json.JSONDecodeError:
                    continue
        
        logger.info(f"Loaded {len(self.data)} examples.")

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        item = self.data[idx]
        encoding = self.tokenizer(
            item['code'],
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(item['label'], dtype=torch.long)
        }

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
    acc = accuracy_score(labels, preds)
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

def train_multilang():
    # Configuration
    model_name = "microsoft/unixcoder-base"
    data_path = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\processed_filtered_owasp_strict_balanced\train.balanced.jsonl"
    output_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\saved_models\unixcoder_multilang"
    
    # Hyperparameters
    epochs = 3
    batch_size = 8 # Adjust based on VRAM (UnixCoder is smaller than LLM)
    learning_rate = 2e-5
    
    # Check Device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    # Load Tokenizer & Model
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    model.to(device)

    # Load Dataset
    # Using a limit for quick testing/validation if needed, remove limit for full training
    full_dataset = MultiLangVulnDataset(data_path, tokenizer, limit=50000) 
    
    # Split Train/Val
    train_size = int(0.9 * len(full_dataset))
    val_size = len(full_dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(full_dataset, [train_size, val_size])
    
    logger.info(f"Train size: {len(train_dataset)}, Val size: {len(val_dataset)}")

    # Training Arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir='./logs',
        logging_steps=100,
        eval_strategy="steps",
        eval_steps=500,
        save_steps=1000,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        fp16=True, # Enable mixed precision for speed
        dataloader_num_workers=0 # Windows compatibility
    )

    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
    )

    # Train
    logger.info("Starting training...")
    trainer.train()
    
    # Save
    logger.info(f"Saving model to {output_dir}")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

if __name__ == "__main__":
    train_multilang()
