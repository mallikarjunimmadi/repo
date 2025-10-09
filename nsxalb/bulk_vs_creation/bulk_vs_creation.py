#!/usr/bin/env python3
"""
bulk_create_vs_full_placement_dryrun.py
----------------------------------------
Universal Avi VS & Pool creation utility (NSX-T + vCenter compatible).

Features:
- Cloud-aware mapping (cloud name → UUID)
- VIP + Pool placement networks (name or UUID)
- Auto-fallback if placement networks invalid
- SE Group assignment
- SNAT and Auto Gateway enabled
- Dry-run mode
- Network pre-check + summary
- Prompts for credentials
- Full logging (console + file)

Requirements:
    pip install avisdk
"""

import argparse
import csv
import datetime
import logging
import os
import sys
import getpass
from avi.sdk.avi_api import ApiSession
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
def setup_logger(log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"avi_vs_create_{ts}.log")

    logger = logging.getLogger("AviVSCreate")
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    )

    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.info(f"Logging initialized → {log_file}")
    return logger


# ---------------------------------------------------------------------
# Fetch Clouds and Networks
# ---------------------------------------------------------------------
def fetch_cloud_map(api, logger):
    """Return dict of {cloud_name: cloud_uuid}."""
    try:
        resp = api.get("cloud").json()
        clouds = {c["name"]: c["uuid"] for c in resp.get("results", [])}
        logger.info(f"Discovered Clouds: {', '.join(clouds.keys())}")
        return clouds
    except Exception as e:
        logger.error(f"Failed to fetch cloud list: {e}")
        return {}


def fetch_networks(api, logger):
    """Return mapping {cloud_uuid: [network_names]}."""
    networks_by_uuid = {}
    try:
        resp = api.get("network").json()
        for net in resp.get("results", []):
            name = net["name"]
            cloud_ref = net.get("cloud_ref", "")
            if not cloud_ref:
                continue
            cloud_uuid = cloud_ref.split("/")[-1]
            networks_by_uuid.setdefault(cloud_uuid, []).append(name)
        total = sum(len(v) for v in networks_by_uuid.values())
        logger.info(f"Discovered {total} networks across {len(networks_by_uuid)} clouds.")
        return networks_by_uuid
    except Exception as e:
        logger.error(f"Failed to fetch networks: {e}")
        return {}


def display_network_summary(cloud_map, networks_by_uuid, logger):
    logger.info("\n📋 Networks available per Cloud:")
    reverse_map = {v: k for k, v in cloud_map.items()}
    for cloud_uuid, nets in networks_by_uuid.items():
        cloud_name = reverse_map.get(cloud_uuid, cloud_uuid)
        logger.info(f"  → {cloud_name} ({len(nets)} networks)")
        for n in sorted(nets):
            logger.info(f"     - {n}")


# ---------------------------------------------------------------------
# Smart network reference builder
# ---------------------------------------------------------------------
def build_network_ref(network_value, cloud_uuid):
    """Return correct network_ref based on whether name or UUID."""
    if not network_value:
        return None
    if network_value.startswith("network-"):  # UUID form
        return f"/api/network/{network_value}"
    else:
        return f"/api/network?name={network_value}&cloud_ref=/api/cloud/{cloud_uuid}"


# ---------------------------------------------------------------------
# Pool creation (with smart fallback)
# ---------------------------------------------------------------------
def create_pool(api, logger, pool_name, members, pool_network=None,
                cloud_name="Default-Cloud", cloud_uuid=None, dry_run=False):
    existing = api.get_object_by_name("pool", pool_name)
    if existing:
        logger.warning(f"Pool '{pool_name}' already exists. Skipping creation.")
        return existing

    servers = []
    for m in members:
        if ":" in m:
            ip, port = m.split(":")
            servers.append({"ip": {"addr": ip.strip(), "type": "V4"}, "port": int(port)})
        elif m.strip():
            servers.append({"ip": {"addr": m.strip(), "type": "V4"}, "port": 80})

    pool_data = {
        "name": pool_name,
        "lb_algorithm": "LB_ALGORITHM_ROUND_ROBIN",
        "servers": servers
    }

    if pool_network:
        net_ref = build_network_ref(pool_network, cloud_uuid)
        if net_ref:
            pool_data["placement_networks"] = [{"network_ref": net_ref}]

    if dry_run:
        logger.info(f"[DRY-RUN] Would create pool '{pool_name}' with {len(servers)} members (Cloud={cloud_name}).")
        return pool_data

    resp = api.post("pool", data=pool_data)
    if resp.status_code in (200, 201):
        logger.info(f"Pool created: {pool_name} (Cloud={cloud_name})")
        return resp.json()

    # Fallback on network error
    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] Pool '{pool_name}' creation failed due to network object; retrying without placement.")
        pool_data.pop("placement_networks", None)
        resp2 = api.post("pool", data=pool_data)
        if resp2.status_code in (200, 201):
            logger.info(f"Pool created (auto-placement): {pool_name}")
            return resp2.json()
        logger.error(f"Pool creation still failed: {resp2.text}")
        return None

    logger.error(f"Failed to create pool '{pool_name}': {resp.text}")
    return None


# ---------------------------------------------------------------------
# VS creation (with smart fallback)
# ---------------------------------------------------------------------
def create_virtual_service(api, logger, vs_name, vs_ip, vs_port, pool_name,
                           vip_network=None, vip_subnet=None, vip_mask=None,
                           se_group=None, cloud_name="Default-Cloud",
                           cloud_uuid=None, dry_run=False):
    existing = api.get_object_by_name("virtualservice", vs_name)
    if existing:
        logger.warning(f"Virtual Service '{vs_name}' already exists. Skipping.")
        return existing

    pool_ref = f"/api/pool?name={pool_name}"
    vip_block = {
        "vip_id": "1",
        "enabled": True,
        "snat": True,
        "auto_allocate_ip": vs_ip.lower() == "auto",
        "auto_allocate_floating_ip": False,
        "avi_allocated_vip": vs_ip.lower() == "auto",
        "auto_allocate_ip_type": "V4_ONLY",
        "auto_allocate_gateway": True
    }

    if vs_ip.lower() != "auto":
        vip_block["ip_address"] = {"addr": vs_ip, "type": "V4"}

    net_ref = build_network_ref(vip_network, cloud_uuid)
    if net_ref and vip_subnet and vip_mask:
        vip_block["placement_networks"] = [{
            "subnet": {"ip_addr": {"addr": vip_subnet, "type": "V4"}, "mask": int(vip_mask)},
            "network_ref": net_ref
        }]

    vs_data = {
        "name": vs_name,
        "vip": [vip_block],
        "services": [{"port": int(vs_port)}],
        "pool_ref": pool_ref,
        "application_profile_ref": "/api/applicationprofile?name=System-Secure-HTTP",
        "network_profile_ref": "/api/networkprofile?name=System-TCP-Proxy",
        "enabled": True
    }

    if se_group:
        vs_data["se_group_ref"] = f"/api/serviceenginegroup?name={se_group}"

    if dry_run:
        logger.info(f"[DRY-RUN] Would create VS '{vs_name}' (VIP={vs_ip}, SEGroup={se_group}, Cloud={cloud_name}).")
        return vs_data

    resp = api.post("virtualservice", data=vs_data)
    if resp.status_code in (200, 201):
        logger.info(f"VS created: {vs_name} | VIP={vs_ip} | SEGroup={se_group} | Cloud={cloud_name}")
        return resp.json()

    # Fallback on network object error
    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] VS '{vs_name}' creation failed due to network object; retrying without placement.")
        vip_block.pop("placement_networks", None)
        vs_data["vip"] = [vip_block]
        resp2 = api.post("virtualservice", data=vs_data)
        if resp2.status_code in (200, 201):
            logger.info(f"VS created (auto-placement): {vs_name}")
            return resp2.json()
        logger.error(f"VS creation still failed: {resp2.text}")
        return None

    logger.error(f"Failed to create VS '{vs_name}': {resp.text}")
    return None


# ---------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Bulk create VS & Pools in Avi with placement")
    parser.add_argument("--controller", help="Avi Controller IP/FQDN (prompted if not provided)")
    parser.add_argument("--username", help="Username for Avi login (prompted if not provided)")
    parser.add_argument("--password", help="Password for Avi login (prompted if not provided)")
    parser.add_argument("--tenant", default="admin", help="Tenant name (default=admin)")
    parser.add_argument("--csv", required=True, help="Path to CSV input file")
    parser.add_argument("--log-dir", default="logs", help="Log directory (default=logs)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without actual creation")
    args = parser.parse_args()

    logger = setup_logger(args.log_dir)
    logger.info(f"Input CSV: {args.csv}")
    logger.info(f"Dry-run mode: {args.dry_run}")

    # Prompt for missing controller/username/password
    if not args.controller:
        args.controller = input("Enter Avi Controller (IP/FQDN): ").strip()
    if not args.username:
        args.username = input("Enter Avi Username: ").strip()
    if not args.password:
        args.password = getpass.getpass("Enter Avi Password: ")
    if not args.tenant:
        args.tenant = "admin"

    try:
        api = ApiSession.get_session(args.controller, args.username, args.password, tenant=args.tenant)
        logger.info(f"Connected to Avi Controller '{args.controller}' as '{args.username}' (tenant={args.tenant})")
    except Exception as e:
        logger.error(f"Failed to connect to Avi Controller '{args.controller}': {e}")
        sys.exit(1)

    # --- Cloud & network discovery ---
    cloud_map = fetch_cloud_map(api, logger)
    if not cloud_map:
        logger.error("Unable to fetch clouds; aborting.")
        sys.exit(1)

    networks_by_uuid = fetch_networks(api, logger)
    display_network_summary(cloud_map, networks_by_uuid, logger)

    if not os.path.exists(args.csv):
        logger.error(f"CSV '{args.csv}' not found.")
        sys.exit(1)

    # --- Process CSV ---
    with open(args.csv, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vs_name = row.get("vs_name")
            vs_ip = row.get("vs_ip")
            vs_port = row.get("vs_port")
            pool_name = row.get("pool_name")
            members = row.get("pool_members", "").split(";")
            vip_network = row.get("vip_network")
            vip_subnet = row.get("vip_subnet")
            vip_mask = row.get("vip_mask")
            pool_network = row.get("pool_network")
            se_group = row.get("se_group")
            cloud_name = row.get("cloud_name") or "Default-Cloud"
            cloud_uuid = cloud_map.get(cloud_name)

            logger.info(f"\n[PROCESSING] VS='{vs_name}' Pool='{pool_name}' Network='{vip_network}' (Cloud={cloud_name})")

            pool_obj = create_pool(api, logger, pool_name, members,
                                   pool_network=pool_network, cloud_name=cloud_name,
                                   cloud_uuid=cloud_uuid, dry_run=args.dry_run)
            if not pool_obj:
                logger.error(f"Skipping VS '{vs_name}' due to pool creation failure.")
                continue

            create_virtual_service(api, logger, vs_name, vs_ip, vs_port, pool_name,
                                   vip_network=vip_network, vip_subnet=vip_subnet,
                                   vip_mask=vip_mask, se_group=se_group,
                                   cloud_name=cloud_name, cloud_uuid=cloud_uuid,
                                   dry_run=args.dry_run)

    logger.info("\n✅ All VS & Pool processing complete.")
    if args.dry_run:
        logger.info("Dry-run completed — no changes applied to controller.")


if __name__ == "__main__":
    main()
