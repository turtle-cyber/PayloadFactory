import os
import logging
from datetime import datetime
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    MongoClient = None

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, uri="mongodb://localhost:27017/", db_name="payloadfactory_ux"):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self.connected = False
        
        if MongoClient:
            try:
                self.client = MongoClient(self.uri, serverSelectionTimeoutMS=2000)
                # Check connection
                self.client.admin.command('ping')
                self.db = self.client[self.db_name]
                self.connected = True
                logger.info(f"Connected to MongoDB: {self.db_name}")
            except Exception as e:
                logger.warning(f"Could not connect to MongoDB: {e}. Running in offline mode.")
        else:
            logger.warning("pymongo not installed. Database features disabled.")

    def save_finding(self, finding):
        """Saves a vulnerability finding to the 'findings' collection."""
        if not self.connected: return
        
        try:
            collection = self.db['findings']
            # Add timestamp
            finding['timestamp'] = datetime.utcnow()
            # Use file_path + location as unique key to prevent duplicates
            key = {'file_path': finding.get('file_path'), 'location': finding.get('location')}
            
            collection.update_one(key, {'$set': finding}, upsert=True)
            logger.debug(f"Saved finding to MongoDB: {finding.get('file_name')}")
        except Exception as e:
            logger.error(f"Failed to save finding to DB: {e}")

    def save_exploit(self, exploit_data):
        """Saves a generated exploit to the 'exploits' collection."""
        if not self.connected: return
        
        try:
            collection = self.db['exploits']
            exploit_data['timestamp'] = datetime.utcnow()
            collection.insert_one(exploit_data)
            logger.info(f"Saved exploit to MongoDB: {exploit_data.get('filename')}")
        except Exception as e:
            logger.error(f"Failed to save exploit to DB: {e}")
