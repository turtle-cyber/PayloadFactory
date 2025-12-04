import os
import logging
from datetime import datetime, timedelta
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    from bson.objectid import ObjectId
except ImportError:
    MongoClient = None
    ObjectId = None

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, uri=None, db_name="payloadfactoryDB"):
        # Use env var if provided, else default
        self.uri = uri or os.getenv("MONGO_URI", "mongodb://admin:admin@localhost:27017/?authSource=admin")
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

    def create_scan(self, project_name, root_path, file_size=0):
        """Creates a new scan record and returns the scan_id."""
        if not self.connected: return None
        
        try:
            collection = self.db['scans']
            scan_doc = {
                'project_name': project_name,
                'root_path': root_path,
                'status': 'processing',
                'stats': {
                    'total_files': 0,
                    'total_vulns': 0,
                    'total_exploits': 0
                },
                'timestamps': {
                    'submitted_at': datetime.utcnow(),
                    'completed_at': None
                },
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'file_size': file_size,
                'progress': {
                    'current_stage': 0,
                    'files_scanned': 0,
                    'total_files': 0,
                    'vulnerabilities_found': 0,
                    'exploits_generated': 0,
                    'current_file': None
                }
            }
            result = collection.insert_one(scan_doc)
            scan_id = result.inserted_id
            logger.info(f"Created new scan: {scan_id}")
            return str(scan_id)
        except Exception as e:
            logger.error(f"Failed to create scan: {e}")
            return None

    def add_file(self, scan_id, file_path, file_size=0):
        """Adds a file to the 'files' collection."""
        if not self.connected or not scan_id: return None
        
        try:
            collection = self.db['files']
            file_doc = {
                'scan_id': scan_id,
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': file_size,
                'file_type': os.path.splitext(file_path)[1],
                'scan_status': 'pending',
                'last_scanned': datetime.utcnow()
            }
            result = collection.insert_one(file_doc)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to add file to DB: {e}")
            return None

    def save_finding(self, finding, scan_id=None, file_id=None):
        """Saves a vulnerability finding to the 'findings' collection."""
        if not self.connected: return
        
        try:
            collection = self.db['findings']
            
            # Generate a unique finding_id if not present
            if 'finding_id' not in finding:
                import hashlib
                unique_str = f"{scan_id}_{finding.get('file_path')}_{finding.get('location')}_{finding.get('line_number')}"
                finding['finding_id'] = hashlib.md5(unique_str.encode()).hexdigest()

            # Enhanced fields
            finding_doc = {
                'scan_id': scan_id,
                'file_id': file_id,
                'finding_id': finding['finding_id'],
                'file_path': finding.get('file_path'),
                'file_name': finding.get('file_name'),
                'location': finding.get('location'),
                'line_number': finding.get('line_number'),
                'vulnerability_type': finding.get('type'),
                'severity': finding.get('severity'),
                'cwe_id': finding.get('cwe_id'),
                'owasp_category': finding.get('owasp_category'),
                'details': finding.get('details'),
                'timestamp': datetime.utcnow(),
                'exploits': [] # Initialize empty exploits list
            }

            # Use finding_id as unique key
            key = {'finding_id': finding['finding_id']}
            
            # If we don't have a scan_id, fall back to old behavior (just file_path/location)
            if not scan_id:
                key = {'file_path': finding.get('file_path'), 'location': finding.get('location')}

            collection.update_one(key, {'$set': finding_doc}, upsert=True)
            logger.debug(f"Saved finding to MongoDB: {finding.get('file_name')} (ID: {finding.get('finding_id')})")
            
            # Update stats if scan_id is present
            if scan_id:
                self.db['scans'].update_one(
                    {'_id': ObjectId(scan_id)},
                    {'$inc': {'stats.total_vulns': 1}}
                )
            
            return finding['finding_id']

        except Exception as e:
            logger.error(f"Failed to save finding to DB: {e}")

    def save_exploit(self, exploit_data, scan_id=None, file_id=None):
        """Saves a generated exploit to the 'findings' collection (nested) or separate collection."""
        if not self.connected: return
        
        try:
            # In the new schema, exploits are nested in findings OR linked.
            # The proposal showed them nested in findings. 
            # But we need to find the RIGHT finding.
            # For simplicity and robustness, let's stick to the proposal: 
            # "exploits": [ ... ] inside the finding document.
            
            # We need to identify the finding this exploit belongs to.
            # Usually exploit_data has 'target_file' and maybe 'cwe'.
            # Ideally we pass the finding_id, but we might not have it easily in current flow.
            # Let's try to match by file_path and cwe/location if possible.
            
            # If we can't easily match, we can just save to a separate 'exploits' collection 
            # and link it, OR just push to the finding if we can find it.
            
            # Let's assume we want to push to the finding document.
            findings_col = self.db['findings']
            
            # Link exploit to finding via finding_id
            query = {
                'finding_id': exploit_data.get('finding_id')
            }
            
            # Fallback if finding_id is missing (should not happen with new logic)
            if not exploit_data.get('finding_id'):
                query = {
                    'scan_id': scan_id,
                    'file_name': exploit_data.get('target_file'),
                    'cwe_id': exploit_data.get('cwe')
                }
            
            # If we can't match a specific finding, maybe we just log it or save to a fallback collection.
            # For now, let's try to push to the first matching finding.
            
            update_result = findings_col.update_one(
                query,
                {
                    '$push': {'exploits': exploit_data},
                    '$set': {'timestamp': datetime.utcnow()} # Update timestamp of finding
                }
            )
            
            if update_result.matched_count == 0:
                logger.warning(f"Could not find parent finding for exploit {exploit_data.get('filename')}. Saving to 'exploits'.")
                self.db['exploits'].insert_one(exploit_data)
            else:
                logger.info(f"Saved exploit to MongoDB finding: {exploit_data.get('filename')}")
                
                if scan_id:
                    self.db['scans'].update_one(
                        {'_id': ObjectId(scan_id)},
                        {'$inc': {'stats.total_exploits': 1}}
                    )

        except Exception as e:
            logger.error(f"Failed to save exploit to DB: {e}")

    def update_scan_status(self, scan_id, status):
        if not self.connected or not scan_id: return
        try:
            self.db['scans'].update_one(
                {'_id': ObjectId(scan_id)},
                {
                    '$set': {
                        'status': status,
                        'timestamps.completed_at': datetime.utcnow() if status in ['completed', 'failed'] else None
                    }
                }
            )
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")

    def update_scan_progress(self, scan_id, updates):
        """Updates scan progress fields using dot notation for nested updates.
        
        Args:
            scan_id: The scan ID string
            updates: Dict with fields to update. Supports dot notation for nested fields
                     e.g., {'status': 'stage-1', 'progress.current_stage': 1}
        """
        if not self.connected or not scan_id: return
        try:
            self.db['scans'].update_one(
                {'_id': ObjectId(scan_id)},
                {'$set': updates}
            )
            logger.debug(f"Updated scan {scan_id} progress: {updates}")
        except Exception as e:
            logger.error(f"Failed to update scan progress: {e}")

    def get_scan(self, scan_id):
        """Retrieves a scan document by its ID.
        
        Args:
            scan_id: The scan ID string
            
        Returns:
            The scan document dict, or None if not found
        """
        if not self.connected or not scan_id: return None
        try:
            scan = self.db['scans'].find_one({'_id': ObjectId(scan_id)})
            if scan:
                scan['_id'] = str(scan['_id'])  # Convert ObjectId to string
            return scan
        except Exception as e:
            logger.error(f"Failed to get scan: {e}")
            return None


    def close_connection(self):
        """Closes the MongoDB connection."""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info("MongoDB connection closed.")

    def save_agent_log(self, log_data):
        """Saves a log entry from a remote agent."""
        if not self.connected: return
        
        try:
            collection = self.db['agent_logs']
            # Ensure timestamp is a datetime object if it's a float/int
            if isinstance(log_data.get('timestamp'), (int, float)):
                log_data['timestamp'] = datetime.fromtimestamp(log_data['timestamp'])
            elif not log_data.get('timestamp'):
                log_data['timestamp'] = datetime.utcnow()
                
            collection.insert_one(log_data)
            logger.info(f"Received agent log from {log_data.get('metadata', {}).get('hostname')}")
        except Exception as e:
            logger.error(f"Failed to save agent log: {e}")

    def get_recent_agent_logs(self, limit=5, seconds=5):
        """Retrieves agent logs from the last N seconds."""
        if not self.connected: return []
        
        try:
            collection = self.db['agent_logs']
            cutoff_time = datetime.utcnow() - timedelta(seconds=seconds)
            
            query = {'timestamp': {'$gte': cutoff_time}}
            logs = list(collection.find(query).sort('timestamp', -1).limit(limit))
            return logs
        except Exception as e:
            logger.error(f"Failed to fetch agent logs: {e}")
            return []

    def get_recent_metrics(self, limit=1, seconds=5):
        """Retrieves agent metrics from the last N seconds."""
        if not self.connected: return []
        
        try:
            collection = self.db['agent_logs']
            cutoff_time = datetime.utcnow() - timedelta(seconds=seconds)
            
            # Filter for type='metric'
            query = {
                'type': 'metric',
                'timestamp': {'$gte': cutoff_time}
            }
            metrics = list(collection.find(query).sort('timestamp', -1).limit(limit))
            return metrics
        except Exception as e:
            logger.error(f"Failed to fetch agent metrics: {e}")
            return []
