from data.database import DatabaseManager
db = DatabaseManager()
devices = db.get_all_devices()
print(f'=== Database Verification Results ===')
print(f'Total devices in DB: {len(devices)}')
print()
print('=== Devices by is_current status ===')
current = [d for d in devices if d.get("is_current") == True]
old = [d for d in devices if d.get("is_current") == False]
print(f'Current scan devices (is_current=True): {len(current)}')
print(f'Old devices (is_current=False): {len(old)}')
print()
if current:
    print('Current scan devices:')
    for dev in current:
        print(f'  - {dev["ip_address"]}: scan_count={dev["scan_count"]}, current_scan_id={dev.get("current_scan_id")}')
print()
if old:
    print(f'Sample old devices (showing first 3):')
    for dev in old[:3]:
        print(f'  - {dev["ip_address"]}: scan_count={dev["scan_count"]}, is_current={dev["is_current"]}')
db.close()
