import pandas as pd
import os
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_dataset():
    # Paths
    base_path = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\exploit-database-master"
    csv_path = os.path.join(base_path, "files.csv")
    output_path = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\custom_exploit_dataset.jsonl"
    
    logger.info(f"Reading metadata from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        return

    logger.info(f"Found {len(df)} entries. Processing...")
    
    count = 0
    with open(output_path, 'w', encoding='utf-8') as f_out:
        for index, row in df.iterrows():
            # Construct file path
            # The 'file' column usually contains relative paths like 'platforms/windows/...'
            # But sometimes might need adjustment.
            rel_path = row['file']
            full_path = os.path.join(base_path, rel_path)
            
            if not os.path.exists(full_path):
                # logger.warning(f"File not found: {full_path}")
                continue
                
            try:
                # Try reading with utf-8, fallback to latin-1 if binary/other
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f_in:
                    code_content = f_in.read()
            except Exception as e:
                logger.warning(f"Error reading {full_path}: {e}")
                continue
            
            # Skip empty files or very small ones
            if len(code_content) < 50:
                continue

            # Create Alpaca format entry
            # Instruction: What the user would ask
            # Input: Context (Platform, Type, etc.)
            # Output: The exploit code
            
            entry = {
                "instruction": f"Generate an exploit for the following vulnerability: {row['description']}",
                "input": f"Platform: {row['platform']}, Type: {row['type']}, Port: {row['port']}, Author: {row['author']}",
                "output": code_content
            }
            
            f_out.write(json.dumps(entry) + "\n")
            count += 1
            
            if count % 1000 == 0:
                logger.info(f"Processed {count} exploits...")

    logger.info(f"Dataset creation complete! Saved {count} examples to {output_path}")

if __name__ == "__main__":
    create_dataset()
