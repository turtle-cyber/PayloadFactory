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

    def create_scan(self, project_name, root_path, file_size=0, recon_scan_id=None):
        """Creates a new scan record and returns the scan_id.
        
        Args:
            project_name: Name of the project being scanned
            root_path: Root path of the source code
            file_size: Total file size in bytes
            recon_scan_id: Optional recon scan ID to link this vulnerability scan to
        """
        if not self.connected: return None
        
        try:
            collection = self.db['scans']
            scan_doc = {
                'project_name': project_name,
                'root_path': root_path,
                'recon_scan_id': recon_scan_id,  # Link to recon scan
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
                # NOTE: Don't include 'exploits' here - it would overwrite existing exploits on update
            }

            # Use finding_id as unique key
            key = {'finding_id': finding['finding_id']}
            
            # If we don't have a scan_id, fall back to old behavior (just file_path/location)
            if not scan_id:
                key = {'file_path': finding.get('file_path'), 'location': finding.get('location')}

            # Use $set for fields and $setOnInsert for exploits initialization
            # This preserves existing exploits on update while initializing on new insert
            collection.update_one(
                key, 
                {
                    '$set': finding_doc,
                    '$setOnInsert': {'exploits': []}  # Only set exploits on first insert
                }, 
                upsert=True
            )
            logger.debug(f"Saved finding to MongoDB: {finding.get('file_name')} (ID: {finding.get('finding_id')})")
            
            # Update stats if scan_id is present
            if scan_id:
                self.db['scans'].update_one(
                    {'_id': ObjectId(scan_id)},
                    {'$inc': {
                        'stats.total_vulns': 1,
                        'progress.vulnerabilities_found': 1
                    }}
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
                        {'$inc': {
                            'stats.total_exploits': 1,
                            'progress.exploits_generated': 1
                        }}
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

    # ========== RECON COLLECTION METHODS ==========
    
    def create_recon_scan(self, target_ip: str, mode: str = "blackbox", scan_name: str = None):
        """Creates a new reconnaissance scan record and returns the recon_scan_id.
        
        Args:
            target_ip: Target IP address being scanned
            mode: "blackbox" or "whitebox"
            scan_name: User-defined name for this scan (optional)
            
        Returns:
            recon_scan_id string or None if failed
        """
        if not self.connected:
            return None
        
        try:
            import uuid
            collection = self.db['recon']
            recon_doc = {
                'scan_id': f"recon_{uuid.uuid4().hex[:12]}",
                'scan_name': scan_name or f"Recon_{target_ip}",
                'target_ip': target_ip,
                'timestamp': datetime.utcnow(),
                'os_info': {
                    'name': 'Unknown',
                    'accuracy': 0,
                    'family': 'Unknown',
                    'vendor': 'Unknown',
                    'os_gen': 'Unknown'
                },
                'services': [],
                'mode': mode,
                'status': 'in_progress'
            }
            result = collection.insert_one(recon_doc)
            logger.info(f"Created recon scan: {recon_doc['scan_id']}")
            return recon_doc['scan_id']
        except Exception as e:
            logger.error(f"Failed to create recon scan: {e}")
            return None

    def update_recon_services(self, recon_scan_id: str, services: list, os_info: dict = None):
        """Updates a recon scan with discovered services and OS info.
        
        Args:
            recon_scan_id: The recon scan ID
            services: List of service dicts from NetworkScanner
            os_info: OS information dict
        """
        if not self.connected or not recon_scan_id:
            return
        
        try:
            collection = self.db['recon']
            update_data = {
                'services': services,
                'scan_time': datetime.utcnow()
            }
            if os_info:
                update_data['os_info'] = os_info
            
            collection.update_one(
                {'scan_id': recon_scan_id},
                {'$set': update_data}
            )
            logger.info(f"Updated recon {recon_scan_id} with {len(services)} services")
        except Exception as e:
            logger.error(f"Failed to update recon services: {e}")

    def update_recon_service_analysis(self, recon_scan_id: str, port: int, analysis: str):
        """Updates a specific service with AIML analysis.
        
        Args:
            recon_scan_id: The recon scan ID
            port: Port number of the service to update
            analysis: AIML generated analysis/guide
        """
        if not self.connected or not recon_scan_id:
            return
        
        try:
            collection = self.db['recon']
            # Update the specific service in the services array
            collection.update_one(
                {'scan_id': recon_scan_id, 'services.port': port},
                {'$set': {'services.$.aiml_analysis': analysis}}
            )
            logger.debug(f"Updated recon service analysis for port {port}")
        except Exception as e:
            logger.error(f"Failed to update service analysis: {e}")

    def complete_recon_scan(self, recon_scan_id: str):
        """Marks a recon scan as completed."""
        if not self.connected or not recon_scan_id:
            return
        
        try:
            collection = self.db['recon']
            collection.update_one(
                {'scan_id': recon_scan_id},
                {'$set': {
                    'status': 'completed',
                    'completed_at': datetime.utcnow()
                }}
            )
            logger.info(f"Completed recon scan: {recon_scan_id}")
        except Exception as e:
            logger.error(f"Failed to complete recon scan: {e}")

    def get_recon_scan(self, recon_scan_id: str):
        """Retrieves a recon scan by its ID.
        
        Returns:
            Recon document dict or None
        """
        if not self.connected or not recon_scan_id:
            return None
        
        try:
            collection = self.db['recon']
            recon = collection.find_one({'scan_id': recon_scan_id})
            if recon:
                recon['_id'] = str(recon['_id'])
            return recon
        except Exception as e:
            logger.error(f"Failed to get recon scan: {e}")
            return None

    def list_recon_scans(self, limit: int = 20, offset: int = 0):
        """Lists all recon scans with pagination.
        
        Returns:
            List of recon documents and total count
        """
        if not self.connected:
            return [], 0
        
        try:
            collection = self.db['recon']
            total = collection.count_documents({})
            scans = list(collection.find()
                        .sort('timestamp', -1)
                        .skip(offset)
                        .limit(limit))
            
            for scan in scans:
                scan['_id'] = str(scan['_id'])
                if 'timestamp' in scan:
                    scan['timestamp'] = scan['timestamp'].isoformat()
            
            return scans, total
        except Exception as e:
            logger.error(f"Failed to list recon scans: {e}")
            return [], 0

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

    # ========== SCAN LOGS ==========
    def save_scan_log(self, scan_id: str, message: str, level: str = "info"):
        """
        Save a log entry for a specific scan.
        This allows real-time log streaming to the frontend.
        """
        if not self.connected:
            return None
        
        try:
            collection = self.db['scan_logs']
            log_doc = {
                'scan_id': scan_id,
                'message': message,
                'level': level.lower(),
                'timestamp': datetime.utcnow()
            }
            result = collection.insert_one(log_doc)
            return str(result.inserted_id)
        except Exception as e:
            # Don't spam error logs for log failures
            pass
        return None

    def get_scan_logs(self, scan_id: str, offset: int = 0, limit: int = 100):
        """
        Get logs for a specific scan with pagination.
        Returns logs and total count.
        """
        if not self.connected:
            return [], 0
        
        try:
            collection = self.db['scan_logs']
            
            # Get total count
            total = collection.count_documents({'scan_id': scan_id})
            
            # Get logs with pagination (sorted by timestamp ascending for chronological order)
            logs = list(collection.find({'scan_id': scan_id})
                       .sort('timestamp', 1)
                       .skip(offset)
                       .limit(limit))
            
            # Convert ObjectId to string for JSON serialization
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log:
                    log['timestamp'] = log['timestamp'].isoformat()
            
            return logs, total
        except Exception as e:
            logger.error(f"Failed to fetch scan logs: {e}")
            return [], 0

    # ========== EXPLOIT LOGS ==========
    def save_exploit_log(self, scan_id: str, exploit_filename: str, phase: str, 
                          message: str, level: str = "info", metrics: dict = None):
        """
        Save a structured log entry for a specific exploit.
        Uses upsert to create document if needed, then $push to append log to array.
        
        Args:
            scan_id: The scan ID
            exploit_filename: Name of the exploit file (e.g., "exploit_XYZ.py")
            phase: Execution phase - "fuzzing", "rl_optimization", "validation", "execution"
            message: Log message
            level: Log level - "info", "warning", "error", "critical", "success"
            metrics: Optional dict with metrics (iteration, payload_size, latency_ms, rce_detected, etc.)
        """
        if not self.connected:
            return None
        
        try:
            collection = self.db['exploit_logs']
            
            # Create the log entry to push to the array
            log_entry = {
                'timestamp': datetime.utcnow(),
                'phase': phase,
                'message': message,
                'level': level.lower(),
                'metrics': metrics or {}
            }
            
            # Upsert: create document if not exists, always push log to array
            collection.update_one(
                {
                    'scan_id': scan_id,
                    'exploit_filename': exploit_filename
                },
                {
                    '$push': {'logs': log_entry},
                    '$set': {'updated_at': datetime.utcnow()},
                    '$setOnInsert': {
                        'scan_id': scan_id,
                        'exploit_filename': exploit_filename,
                        'status': 'in_progress',
                        'created_at': datetime.utcnow()
                    }
                },
                upsert=True
            )
            return True
        except Exception as e:
            # Don't spam error logs for log failures
            pass
        return None
    
    def update_exploit_status(self, scan_id: str, exploit_filename: str, status: str):
        """
        Update the status of an exploit execution.
        
        Args:
            scan_id: The scan ID
            exploit_filename: Name of the exploit file
            status: "not_started", "in_progress", "completed", "failed"
        """
        if not self.connected:
            return
        
        try:
            collection = self.db['exploit_logs']
            collection.update_one(
                {
                    'scan_id': scan_id,
                    'exploit_filename': exploit_filename
                },
                {
                    '$set': {
                        'status': status,
                        'updated_at': datetime.utcnow()
                    }
                },
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to update exploit status: {e}")
    
    def get_exploit_logs(self, scan_id: str, exploit_filename: str) -> list:
        """
        Retrieve all logs for a specific exploit.
        
        Args:
            scan_id: The scan ID
            exploit_filename: Name of the exploit file
            
        Returns:
            List of log entries sorted by timestamp
        """
        if not self.connected:
            return []
        
        try:
            collection = self.db['exploit_logs']
            doc = collection.find_one({
                'scan_id': scan_id,
                'exploit_filename': exploit_filename
            })
            
            if not doc or 'logs' not in doc:
                return []
            
            logs = doc['logs']
            
            # Convert timestamps to ISO format for JSON serialization
            for i, log in enumerate(logs):
                log['_id'] = f"{doc['_id']}_{i}"  # Create unique ID per log entry
                if 'timestamp' in log and hasattr(log['timestamp'], 'isoformat'):
                    log['timestamp'] = log['timestamp'].isoformat()
            
            return logs
        except Exception as e:
            logger.error(f"Failed to fetch exploit logs: {e}")
            return []
    
    def get_exploit_status(self, scan_id: str, exploit_filename: str) -> str:
        """
        Get the execution status of an exploit.
        
        Returns:
            "not_started" | "in_progress" | "completed" | "failed"
        """
        if not self.connected:
            return "not_started"
        
        try:
            collection = self.db['exploit_logs']
            
            doc = collection.find_one({
                'scan_id': scan_id,
                'exploit_filename': exploit_filename
            })
            
            if not doc:
                return "not_started"
            
            return doc.get('status', 'in_progress')
        except Exception as e:
            logger.error(f"Failed to get exploit status: {e}")
            return "not_started"

    def clear_database(self):
        """Cleans all data from the database (scans, files, findings, logs)."""
        if not self.connected: return False
        
        try:
            # Drop collections but keep indexes/structure if needed
            # Or simpler: dropDatabase() but we might want to keep some config?
            # Safe approach: Delete all documents from known collections
            
            collections = ['scans', 'files', 'findings', 'exploits', 'agent_logs', 'recon', 'scan_logs', 'exploit_logs']
            
            for col_name in collections:
                self.db[col_name].delete_many({})
                logger.info(f"Cleared collection: {col_name}")
            
            logger.info("Database cleared successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to clear database: {e}")
            return False
