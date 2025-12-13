"""Check exploit logs in MongoDB"""
from ml_engine.db_manager import DatabaseManager

db = DatabaseManager()

if db.connected:
    # Check exploit_logs collection
    collection = db.db['exploit_logs']
    logs = list(collection.find().limit(5))
    print(f"exploit_logs collection: {len(logs)} documents")
    
    for log in logs:
        filename = log.get('exploit_filename', 'Unknown')
        log_count = len(log.get('logs', []))
        status = log.get('current_status', 'Unknown')
        print(f"  {filename}: {log_count} log entries, status: {status}")
    
    # Also check the most recent scan's status
    print("\nMost recent scans:")
    scans = list(db.db['scans'].find().sort('timestamps.submitted_at', -1).limit(3))
    for s in scans:
        print(f"  ID: {s['_id']}")
        print(f"    remote_host: {s.get('remote_host', 'NOT SET')}")
        print(f"    status: {s.get('status')}")
else:
    print("Database not connected")
