import json
import pandas as pd
import os
from tqdm import tqdm
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataLoader:
    def __init__(self, dataset_path, output_dir):
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def load_diversevul(self, limit=None):
        """
        Loads the DiverseVul dataset from a JSONL file.
        """
        logging.info(f"Loading DiverseVul dataset from {self.dataset_path}")
        data = []
        try:
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                for i, line in tqdm(enumerate(f)):
                    if limit and i >= limit:
                        break
                    try:
                        item = json.loads(line)
                        # Extract relevant fields
                        # DiverseVul usually has: func, target, cwe, project, commit_id
                        func_code = item.get('func', '')
                        target = item.get('target', 0)
                        cwe = item.get('cwe', [])
                        
                        if func_code:
                            data.append({
                                'code': func_code,
                                'label': int(target),
                                'cwe': cwe
                            })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logging.error(f"File not found: {self.dataset_path}")
            return None

        df = pd.DataFrame(data)
        logging.info(f"Loaded {len(df)} samples.")
        return df

    def preprocess(self, df):
        """
        Basic preprocessing: remove duplicates, handle missing values.
        """
        logging.info("Preprocessing data...")
        initial_len = len(df)
        df = df.drop_duplicates(subset=['code'])
        df = df.dropna(subset=['code', 'label'])
        logging.info(f"Removed {initial_len - len(df)} duplicates/NaNs.")
        return df

    def save_splits(self, df, train_ratio=0.8):
        """
        Saves train/test splits to CSV.
        """
        from sklearn.model_selection import train_test_split
        
        logging.info("Splitting data into train and test sets...")
        train_df, test_df = train_test_split(df, train_size=train_ratio, stratify=df['label'], random_state=42)
        
        train_path = os.path.join(self.output_dir, 'train.csv')
        test_path = os.path.join(self.output_dir, 'test.csv')
        
        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)
        
        logging.info(f"Saved train set to {train_path} ({len(train_df)} samples)")
        logging.info(f"Saved test set to {test_path} ({len(test_df)} samples)")

if __name__ == "__main__":
    # Configuration
    DATASET_PATH = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\diversevul\diversevul_20230702.json"
    OUTPUT_DIR = r"C:\Users\intel\Desktop\PayloadFactoryUX\ml_engine\data"
    
    # Limit for testing purposes (set to None for full dataset)
    LIMIT = 10000 
    
    loader = DataLoader(DATASET_PATH, OUTPUT_DIR)
    df = loader.load_diversevul(limit=LIMIT)
    
    if df is not None and not df.empty:
        df = loader.preprocess(df)
        loader.save_splits(df)
        print("Data ingestion complete.")
    else:
        print("Failed to load data.")
