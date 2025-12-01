import json
import pandas as pd
import os

def convert_jsonl_to_csv(jsonl_path, csv_path, max_code_length=1024):
    """
    Convert JSONL dataset to CSV format for training.
    
    Args:
        jsonl_path: Path to input JSONL file
        csv_path: Path to output CSV file
        max_code_length: Maximum code length to include (for memory efficiency)
    """
    print(f"Converting {jsonl_path} to {csv_path}...")
    
    data = []
    skipped = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                record = json.loads(line)
                code = record.get('code', '')
                label = record.get('label_binary')
                cwe_list = record.get('cwe_list', [])
                
                # Skip if no code or label
                if not code or label is None:
                    skipped += 1
                    continue
                
                # Truncate very long code samples
                if len(code) > max_code_length:
                    code = code[:max_code_length]
                
                # Format CWE list as string
                cwe_str = str(cwe_list) if cwe_list else "[]"
                
                data.append({
                    'code': code,
                    'label': label,
                    'cwe': cwe_str
                })
                
                if line_num % 5000 == 0:
                    print(f"Processed {line_num} records, collected {len(data)} valid samples...")
                    
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")
                skipped += 1
                continue
    
    # Create DataFrame and save
    df = pd.DataFrame(data)
    df.to_csv(csv_path, index=False)
    
    print(f"\nConversion complete!")
    print(f"Total valid samples: {len(data)}")
    print(f"Skipped samples: {skipped}")
    print(f"Label distribution:")
    print(df['label'].value_counts())
    print(f"\nSaved to: {csv_path}")

if __name__ == "__main__":
    base_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\processed_filtered_owasp_strict_balanced"
    output_dir = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\data_balanced"
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Convert each split
    splits = {
        'train': 'train.balanced.jsonl',
        'val': 'val.balanced.jsonl',
        'test': 'test.balanced.jsonl'
    }
    
    for split_name, filename in splits.items():
        jsonl_path = os.path.join(base_dir, filename)
        csv_path = os.path.join(output_dir, f'{split_name}.csv')
        
        if os.path.exists(jsonl_path):
            convert_jsonl_to_csv(jsonl_path, csv_path)
            print("\n" + "="*60 + "\n")
        else:
            print(f"Warning: {jsonl_path} not found, skipping...")
