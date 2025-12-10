"""
Debug script to check if scan logs are being saved to MongoDB
"""
from ml_engine.db_manager import DatabaseManager

db = DatabaseManager()

print("=" * 50)
print("SCAN LOGS DEBUG")
print("=" * 50)

if not db.connected:
    print("ERROR: Not connected to MongoDB!")
else:
    print("✓ Connected to MongoDB")
    
    # Get all scan_logs
    try:
        scan_logs = list(db.db['scan_logs'].find().limit(10))
        print(f"\nTotal scan_logs in collection: {db.db['scan_logs'].count_documents({})}")
        
        if scan_logs:
            print("\nSample logs:")
            for log in scan_logs[:5]:
                print(f"  - [{log.get('level', 'INFO')}] {log.get('scan_id', 'N/A')[:8]}... : {log.get('message', 'N/A')[:50]}")
        else:
            print("\n⚠️ NO LOGS FOUND in scan_logs collection!")
            
        # Also list all scans to get valid scan_ids
        scans = list(db.db['scans'].find().limit(5))
        print(f"\n\nRecent scans ({db.db['scans'].count_documents({})} total):")
        for scan in scans:
            scan_id = str(scan.get('_id', ''))
            print(f"  - {scan_id} : {scan.get('status', 'unknown')} / {scan.get('project_name', 'N/A')}")
            
            # Check if this scan has logs
            log_count = db.db['scan_logs'].count_documents({'scan_id': scan_id})
            print(f"    → Logs: {log_count}")
            
    except Exception as e:
        print(f"ERROR: {e}")

print("\n" + "=" * 50)
