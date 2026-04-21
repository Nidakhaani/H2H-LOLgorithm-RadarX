from data.database import DatabaseManager
db = DatabaseManager()
devices = db.get_all_devices()
print(f'Total devices: {len(devices)}')
if devices:
    dev = devices[0]
    print(f'Sample device: {dev["ip_address"]} - is_current: {dev["is_current"]} - scan_count: {dev["scan_count"]}')
    print(f'✓ New fields present: is_current={dev.get("is_current")}, current_scan_id={dev.get("current_scan_id")}')
db.close()
