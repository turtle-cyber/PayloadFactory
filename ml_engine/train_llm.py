import os
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model
from trl import SFTTrainer, SFTConfig
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def train_llm():
    # Configuration
    model_path = r"E:\GRAND_AI_MODELS\hermes-3-llama-3.1-8b"
    dataset_path = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\custom_exploit_dataset.jsonl"
    output_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\saved_models\hermes_adapter"
    
    # Load Dataset
    dataset = load_dataset("json", data_files=dataset_path, split="train")
    
    # Hyperparameters
    num_epochs = 1
    batch_size = 1 # Small batch size for 12GB VRAM
    gradient_accumulation_steps = 4
    learning_rate = 2e-4
    
    logger.info(f"Loading model from {model_path}...")
    
    # 4-bit Quantization Config
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    # Load Model
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        quantization_config=bnb_config,
        device_map="auto",
        use_cache=False # Required for training
    )
    
    # Prepare for k-bit training
    model = prepare_model_for_kbit_training(model)

    # Load Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # LoRA Config
    peft_config = LoraConfig(
        lora_alpha=16,
        lora_dropout=0.1,
        r=8, # Rank
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    )

    # model = get_peft_model(model, peft_config) # Handled by SFTTrainer
    # model.print_trainable_parameters()

    def formatting_prompts_func(example):
        ALPACA_PROMPT_INPUT = (
            "Below is an instruction that describes a task, paired with an input that provides further context. "
            "Write a response that appropriately completes the request.\n\n"
            "### Instruction:\n{instruction}\n\n### Input:\n{input}\n\n### Response:\n{output}"
        )
        ALPACA_PROMPT_NO_INPUT = (
            "Below is an instruction that describes a task. "
            "Write a response that appropriately completes the request.\n\n"
            "### Instruction:\n{instruction}\n\n### Response:\n{output}"
        )
        
        output_texts = []

        if isinstance(example['instruction'], list):
            for i in range(len(example['instruction'])):
                instruction = example['instruction'][i]
                input_text = example.get('input', [''])[i]
                output = example['output'][i]
                
                if input_text and input_text.strip():
                    text = ALPACA_PROMPT_INPUT.format(instruction=instruction, input=input_text, output=output)
                else:
                    text = ALPACA_PROMPT_NO_INPUT.format(instruction=instruction, output=output)
                output_texts.append(text)
            return output_texts
        else:
            # Single example
            instruction = example['instruction']
            input_text = example.get('input', "")
            output = example['output']
            
            if input_text and input_text.strip():
                text = ALPACA_PROMPT_INPUT.format(instruction=instruction, input=input_text, output=output)
            else:
                text = ALPACA_PROMPT_NO_INPUT.format(instruction=instruction, output=output)
            return text

    # Training Arguments (SFTConfig)
    training_args = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        optim="paged_adamw_32bit",
        save_steps=100,
        logging_steps=10,
        learning_rate=learning_rate,
        weight_decay=0.001,
        fp16=False,
        bf16=True, # Better for RTX 5070
        max_grad_norm=0.3,
        warmup_ratio=0.03,
        group_by_length=True,
        gradient_checkpointing=True, # Essential for VRAM saving
        gradient_checkpointing_kwargs={"use_reentrant": False},
        lr_scheduler_type="constant",
        max_length=512, # Correct parameter name
        dataset_text_field="text", 
        packing=False
    )

    # Trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=peft_config,
        processing_class=tokenizer, # Renamed from tokenizer
        args=training_args,
        formatting_func=formatting_prompts_func,
    )

    logger.info("Starting training...")
    trainer.train()
    
    logger.info(f"Saving adapter to {output_dir}")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

if __name__ == "__main__":
    train_llm()
