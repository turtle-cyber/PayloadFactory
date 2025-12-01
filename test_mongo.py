import os
import sys
import logging
from datetime import datetime

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from ml_engine.db_manager import DatabaseManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_mongo_insert():
    logger.info("Testing MongoDB insertion...")
    db = DatabaseManager()
    
    if not db.connected:
        logger.error("MongoDB not connected! Cannot test.")
        return

    # Simulate Stage 1 Finding
    finding_stage_1 = {
        'file_path': 'C:\\Users\\intel\\Desktop\\test.java',
        'file_name': 'test.java',
        'vulnerabilities': [{'line': 10, 'confidence': 0.9}],
        'stage': 1
    }
    
    logger.info("Attempting Stage 1 save...")
    try:
        db.save_finding(finding_stage_1)
        logger.info("Stage 1 save successful.")
    except Exception as e:
        logger.error(f"Stage 1 save failed: {e}")

    # Simulate Stage 2 Finding (Update)
    finding_stage_2 = {
        'file_path': 'C:\\Users\\intel\\Desktop\\test.java',
        'file_name': 'test.java',
        'vulnerabilities': [{'line': 10, 'confidence': 0.9, 'classification': {'cwe': 'CWE-89'}}],
        'stage': 2
    }
    
    logger.info("Attempting Stage 2 save...")
    try:
        db.save_finding(finding_stage_2)
        logger.info("Stage 2 save successful.")
    except Exception as e:
        logger.error(f"Stage 2 save failed: {e}")

if __name__ == "__main__":
    test_mongo_insert()
