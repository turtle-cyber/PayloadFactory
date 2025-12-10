"""Check MongoDB findings data for orphaned entries without proper scan_id"""
from ml_engine.db_manager import DatabaseManager

db = DatabaseManager()

if db.connected:
    # Count findings by scan_id
    pipeline = [
        {"$group": {"_id": "$scan_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    scan_groups = list(db.db['findings'].aggregate(pipeline))
    
    print("=" * 50)
    print("FINDINGS BY SCAN_ID")
    print("=" * 50)
    for group in scan_groups:
        scan_id = group['_id']
        count = group['count']
        label = "NULL/NONE" if scan_id is None else str(scan_id)[:20] + "..."
        print(f"{label}: {count} findings")
    
    total = db.db['findings'].count_documents({})
    print(f"\nTOTAL FINDINGS IN DATABASE: {total}")
    
    # Count scans
    scan_count = db.db['scans'].count_documents({})
    print(f"TOTAL SCANS IN DATABASE: {scan_count}")
else:
    print("MongoDB not connected!")
