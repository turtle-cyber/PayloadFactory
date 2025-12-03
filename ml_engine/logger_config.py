import logging
import json
import datetime
import sys

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logger(name, log_file="scan_log.json", level=logging.INFO):
    """
    Sets up a logger that writes JSON to a file and Text to the console.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to prevent duplicates if called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()
        
    # File Handler (JSON)
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)
    
    # Stream Handler (Console - Text for readability)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)
        
    return logger
