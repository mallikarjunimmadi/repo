import requests
import urllib3
import argparse
import getpass
import datetime
import csv
import re
import time

from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Export per-binding discovered and realized info from NSX Manager.")
parser.add_argument('-n', '--nsxmgr', help='NSX Manager FQDN or IP address')
parser.add_argument('-u', '--username', help='Username')
parser.add_argument('-p', '--password', help='Password (if not supplied, will prompt securely)')
parser.add_argument('--include-segment', help='Only include segment(s) matching this substring (optional)')
parser.add_argument('-t', '--threads', type=int, default=10, help='Number of parallel threads (default: 10)')
args = parser.parse_args()

# Credentials
nsx_mgr = args.nsxmgr if args.nsxmgr else input("NSX Manager FQDN/IP: ")
username = args.username if args.username else input("Username: ")
password = args.password if args.password else getpass.getpass("Password: ")
segment_filter = args.include_segment
max_threads = args.threads

# Requests session
session = requests.Session()
session.auth = (username, password)
session.verify = False
session.headers.update({'Content-Type': 'application/json'})
session.trust_env = False

def nsx_get(path, retries=3):
    url = f"https://{nsx_mgr}/policy/api/v1{path}"
    for attempt in range(retries):
        try:
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = 2 ** attempt
                print(f"[429] Rate limited: {url}. Retrying in {wait}s...")
                time.sleep(wait)
                continue
            else:
                print(f"[ERROR] GET {url} failed: {resp.status_code}")
                return None
        except Exception as e:
            print(f"[EXCEPTION] GET {url}: {e}")
            return None
    print(f"[FAILED] GET {url} after {retries} retries.")
    return None

def convert_timestamp(epoch_ms):
    try:
        return datetime.datetime.fromtimestamp(int(epoch_ms) / 1000).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "N/A"

def process_port(segment_id, segment_name, port):
    port_id = port['id']
    display_name = port.get('display_name', 'unknown')
    vm_name = display_name.split('.')[0] if '.' in display_name else display_name

    state = nsx_get(f"/infra/segments/{segment_id}/ports/{port_id}/state")
    rows = []

    if not state:
        return rows

    # Discovered bindings
    d_bind = state.get('discovered_bindings', [])
    d_vmtools = [b for b in d_bind if b.get('source') == 'VM_TOOLS']
    d_arp = [b for b in d_bind if b.get('source') == 'ARP_SNOOPING']
    d_fallback = [b for b in d_bind if b.get('source') not in ['VM_TOOLS', 'ARP_SNOOPING']]
    selected = d_vmtools if d_vmtools else d_arp if d_arp else d_fallback

    for b in selected:
        binding = b.get('binding', {})
        ip = binding.get('ip_address', 'N/A')
        mac = binding.get('mac_address', 'N/A')
        timestamp = convert_timestamp(b.get('binding_timestamp'))
        source_type = f"DISCOVERED-{b.get('source', 'UNKNOWN')}"
        rows.append({
            "VM Name": vm_name,
            "Segment Name": segment_name,
            "IP Address": ip,
            "MAC Address": mac,
            "Source Type": source_type,
            "Timestamp": timestamp
        })

    # Realized bindings
    r_bind = state.get('realized_bindings', [])
    r_vmtools = [b for b in r_bind if b.get('source') == 'VM_TOOLS']
    r_arp = [b for b in r_bind if b.get('source') == 'ARP_SNOOPING']
    r_fallback = [b for b in r_bind if b.get('source') not in ['VM_TOOLS', 'ARP_SNOOPING']]
    r_selected = r_vmtools if r_vmtools else r_arp if r_arp else r_fallback

    for b in r_selected:
        binding = b.get('binding', {})
        ip = binding.get('ip_address', 'N/A')
        mac = binding.get('mac_address', 'N/A')
        timestamp = convert_timestamp(b.get('binding_timestamp'))
        source_type = f"REALIZED-{b.get('source', 'UNKNOWN')}"
        rows.append({
            "VM Name": vm_name,
            "Segment Name": segment_name,
            "IP Address": ip,
            "MAC Address": mac,
            "Source Type": source_type,
            "Timestamp": timestamp
        })

    print(f"[INFO] Processed: {vm_name}")
    return rows

# Fetch segments
print("[*] Fetching segments...")
segments = nsx_get("/infra/segments")
if not segments or "results" not in segments:
    print("[ERROR] Unable to fetch segments.")
    exit(1)

segment_list = segments["results"]
if segment_filter:
    segment_list = [s for s in segment_list if segment_filter.lower() in s.get('display_name', '').lower()]

print(f"[*] {len(segment_list)} segments matched.")

segment_port_tasks = []
for segment in segment_list:
    segment_id = segment['id']
    segment_name = segment['display_name']
    ports = nsx_get(f"/infra/segments/{segment_id}/ports")
    if ports:
        for port in ports.get("results", []):
            segment_port_tasks.append((segment_id, segment_name, port))

print(f"[*] {len(segment_port_tasks)} ports found.")

# Process ports in parallel
results = []
with ThreadPoolExecutor(max_workers=max_threads) as executor:
    futures = [executor.submit(process_port, seg_id, seg_name, port) for seg_id, seg_name, port in segment_port_tasks]
    for future in as_completed(futures):
        results.extend(future.result())

# Write CSV
timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
safe_mgr = re.sub(r'[^A-Za-z0-9.\-]', '_', nsx_mgr)
csv_file = f"{safe_mgr}_{timestamp}.csv"

headers = ["VM Name", "Segment Name", "IP Address", "MAC Address", "Source Type", "Timestamp"]

with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=headers)
    writer.writeheader()
    writer.writerows(results)

print(f"[✔] Export completed: {csv_file}")
