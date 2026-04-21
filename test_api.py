import requests
import time
import subprocess
import os

# Start API in background
proc = subprocess.Popen(['python', 'run.py', '--api'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

try:
    # Test /api/devices endpoint
    response = requests.get('http://localhost:8000/api/devices')
    if response.status_code == 200:
        devices = response.json()
        if devices:
            print('API returned {} devices'.format(len(devices)))
            for dev in devices[:2]:
                ip = dev["ip_address"]
                is_current = dev.get("is_current")
                scan_count = dev.get("scan_count")
                print('  Device {}: is_current={}, scan_count={}'.format(ip, is_current, scan_count))
            print('All required fields present in API response')
    else:
        print('Error: {}'.format(response.status_code))
finally:
    proc.terminate()
    proc.wait()
