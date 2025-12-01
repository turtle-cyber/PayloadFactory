"""
Transfer Learning Script for Vulnerability Scanner Models

Retrains UnixCoder and GraphCodeBERT using the balanced dataset.
This fixes the overfitting issue caused by the imbalanced training data.
"""

import torch
import os
import pandas as pd
import argparse
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback
)
from torch.utils.data import Dataset
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check GPU
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
        logger.info(f"Loaded {len(self.data)} samples from {csv_file}")
        logger.info(f"Label distribution:\n{self.data['label'].value_counts()}")

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

def retrain_model(
    model_name,
    data_dir,
    output_dir,
    epochs=3,
    batch_size=8,
    learning_rate=2e-5,
    load_existing=True
):
    """
    Retrain a model using transfer learning.
    
    Args:
        model_name: Model to retrain (e.g., "microsoft/unixcoder-base")
        data_dir: Directory containing train.csv and val.csv
        output_dir: Where to save the retrained model
        epochs: Number of training epochs
        batch_size: Training batch size
        learning_rate: Learning rate for fine-tuning
        load_existing: If True, continue from existing checkpoint
    """
    logger.info(f"={60}")
    logger.info(f"Retraining {model_name}")
    logger.info(f"={60}")
    
    # Load tokenizer
    logger.info(f"Loading tokenizer for {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    
    # Prepare dataset paths
    train_path = os.path.join(data_dir, 'train.csv')
    val_path = os.path.join(data_dir, 'val.csv')
    test_path = os.path.join(data_dir, 'test.csv')
    
    if not os.path.exists(train_path):
        logger.error(f"Training data not found at {train_path}")
        return
    
    # Load datasets
    logger.info("Loading datasets...")
    train_dataset = VulnerabilityDataset(train_path, tokenizer)
    val_dataset = VulnerabilityDataset(val_path, tokenizer) if os.path.exists(val_path) else None
    
    # Load or create model
    if load_existing and os.path.exists(output_dir) and os.path.exists(os.path.join(output_dir, "config.json")):
        logger.info(f"Loading existing model checkpoint from {output_dir} for transfer learning...")
        model = AutoModelForSequenceClassification.from_pretrained(output_dir, num_labels=2)
    else:
        logger.info(f"Loading base model {model_name}...")
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size * 2,
        learning_rate=learning_rate,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=os.path.join(output_dir, 'logs'),
        logging_steps=100,
        eval_strategy="steps" if val_dataset else "no",
        eval_steps=500 if val_dataset else None,
        save_strategy="steps",
        save_steps=1000,
        save_total_limit=2,
        load_best_model_at_end=True if val_dataset else False,
        metric_for_best_model="eval_loss" if val_dataset else None,
        greater_is_better=False,
        fp16=torch.cuda.is_available(),  # Use mixed precision if GPU available
        dataloader_num_workers=0,  # Avoid multiprocessing issues on Windows
        report_to="none"  # Disable wandb/tensorboard
    )
    
    # Callbacks
    callbacks = []
    if val_dataset:
        callbacks.append(EarlyStoppingCallback(early_stopping_patience=3))
    
    # Create trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        callbacks=callbacks
    )
    
    # Train
    logger.info("Starting transfer learning...")
    logger.info(f"Training on {len(train_dataset)} samples")
    if val_dataset:
        logger.info(f"Validating on {len(val_dataset)} samples")
    
    trainer.train()
    
    # Save final model
    logger.info(f"Saving retrained model to {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    logger.info(f"Transfer learning complete for {model_name}!")
    logger.info("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrain Vulnerability Detection Models")
    parser.add_argument(
        "--model",
        type=str,
        choices=["unixcoder", "graphcodebert", "both"],
        default="both",
        help="Which model to retrain"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=8,
        help="Training batch size (reduce if OOM)"
    )
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=2e-5,
        help="Learning rate for fine-tuning"
    )
    
    args = parser.parse_args()
    
    # Paths
    data_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\data_balanced"
    base_output_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\saved_models"
    
    # Model configurations
    models = {
        "unixcoder": {
            "name": "microsoft/unixcoder-base",
            "output_dir": os.path.join(base_output_dir, "unixcoder")
        },
        "graphcodebert": {
            "name": "microsoft/graphcodebert-base",
            "output_dir": os.path.join(base_output_dir, "graphcodebert")
        }
    }
    
    # Train selected models
    if args.model == "both":
        for model_key in ["unixcoder", "graphcodebert"]:
            config = models[model_key]
            retrain_model(
                model_name=config["name"],
                data_dir=data_dir,
                output_dir=config["output_dir"],
                epochs=args.epochs,
                batch_size=args.batch_size,
                learning_rate=args.learning_rate,
                load_existing=True  # Transfer learning from existing checkpoint
            )
            print("\n" + "="*60 + "\n")
    else:
        config = models[args.model]
        retrain_model(
            model_name=config["name"],
            data_dir=data_dir,
            output_dir=config["output_dir"],
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            load_existing=True
        )
    
    print("\n🎉 All retraining complete! Models saved to ml_engine/saved_models/")
    print("You can now test the scanner with: python debug_scanner.py")
