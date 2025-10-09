#!/usr/bin/env python3
"""
bulk_create_vs_full_placement_dryrun.py
---------------------------------------
Create multiple Virtual Services and Pools in VMware NSX Advanced Load Balancer (Avi)
using a CSV file.  Supports NSX-T and vCenter clouds.

Features
--------
✓ Cloud-aware object creation (Pool, VS, VS-VIP)
✓ NSX-T vip_network_ref vs placement_networks auto-handling
✓ SNAT + Auto-Gateway enabled
✓ Dry-run preview mode
✓ Smart retry if network not found
✓ Credential prompting
✓ Cloud/network pre-summary
✓ --debug  →  detailed API payloads/responses in log file
"""

import argparse, csv, datetime, logging, os, sys, getpass
from avi.sdk.avi_api import ApiSession
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
def setup_logger(log_dir="logs", debug=False):
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"avi_vs_create_{ts}.log")
    logger = logging.getLogger("AviVSCreate")
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                          "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.info(f"Logging initialized → {log_file}")
    if debug:
        logger.info("Debug mode enabled — full payloads/responses logged.")
    return logger


# ---------------------------------------------------------------------
# Cloud / Network discovery
# ---------------------------------------------------------------------
def fetch_cloud_map(api, logger):
    try:
        clouds = {c["name"]: c["uuid"] for c in api.get("cloud").json().get("results", [])}
        logger.info(f"Discovered Clouds: {', '.join(clouds.keys())}")
        return clouds
    except Exception as e:
        logger.error(f"Failed to fetch clouds: {e}")
        return {}

def fetch_networks(api, logger):
    nets_by_uuid = {}
    try:
        for net in api.get("network").json().get("results", []):
            cloud_uuid = net.get("cloud_ref", "").split("/")[-1]
            nets_by_uuid.setdefault(cloud_uuid, []).append(net["name"])
        logger.info(f"Discovered {sum(len(v) for v in nets_by_uuid.values())} networks across {len(nets_by_uuid)} clouds.")
        return nets_by_uuid
    except Exception as e:
        logger.error(f"Failed to fetch networks: {e}")
        return {}

def display_network_summary(cloud_map, nets_by_uuid, logger):
    logger.info("\n📋 Networks available per Cloud:")
    rev = {v: k for k, v in cloud_map.items()}
    for cu, names in nets_by_uuid.items():
        cname = rev.get(cu, cu)
        logger.info(f"  → {cname} ({len(names)} networks)")
        for n in sorted(names):
            logger.info(f"     - {n}")


# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------
def build_network_ref(net, cloud_uuid):
    if not net:
        return None
    return f"/api/network/{net}" if net.startswith("network-") else f"/api/network?name={net}&cloud_ref=/api/cloud/{cloud_uuid}"


# ---------------------------------------------------------------------
# Pool creation
# ---------------------------------------------------------------------
def create_pool(api, logger, name, members, pool_network, cloud_uuid, cloud_name, dry, debug):
    existing = api.get_object_by_name("pool", name)
    if existing:
        logger.warning(f"Pool '{name}' already exists. Skipping creation.")
        return existing

    servers = []
    for m in members:
        if ":" in m:
            ip, port = m.split(":")
            servers.append({"ip": {"addr": ip.strip(), "type": "V4"}, "port": int(port)})
        elif m.strip():
            servers.append({"ip": {"addr": m.strip(), "type": "V4"}, "port": 80})

    pdata = {
        "name": name,
        "cloud_ref": f"/api/cloud/{cloud_uuid}",
        "lb_algorithm": "LB_ALGORITHM_ROUND_ROBIN",
        "servers": servers
    }

    if pool_network:
        ref = build_network_ref(pool_network, cloud_uuid)
        if ref:
            pdata["placement_networks"] = [{"network_ref": ref}]

    if debug:
        logger.debug(f"[POOL PAYLOAD] {pdata}")

    if dry:
        logger.info(f"[DRY-RUN] Would create Pool '{name}' in {cloud_name}.")
        return pdata

    resp = api.post("pool", data=pdata)
    if debug:
        logger.debug(f"[POOL RESPONSE] {resp.status_code} → {resp.text}")

    if resp.status_code in (200, 201):
        logger.info(f"Pool created: {name} (Cloud={cloud_name})")
        return resp.json()

    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] Pool '{name}' failed due to network object; retrying without placement.")
        pdata.pop("placement_networks", None)
        resp2 = api.post("pool", data=pdata)
        if debug:
            logger.debug(f"[POOL RETRY RESPONSE] {resp2.status_code} → {resp2.text}")
        if resp2.status_code in (200, 201):
            logger.info(f"Pool created (auto-placement): {name}")
            return resp2.json()

    logger.error(f"Pool create failed: {resp.text}")
    return None


# ---------------------------------------------------------------------
# Virtual Service creation
# ---------------------------------------------------------------------
def create_vs(api, logger, vs_name, vs_ip, vs_port, pool_name,
              vip_net, vip_subnet, vip_mask, se_group,
              cloud_uuid, cloud_name, dry, debug):
    existing = api.get_object_by_name("virtualservice", vs_name)
    if existing:
        logger.warning(f"VS '{vs_name}' already exists. Skipping.")
        return existing

    pool_ref = f"/api/pool?name={pool_name}"
    vdata = {
        "name": vs_name,
        "cloud_ref": f"/api/cloud/{cloud_uuid}",
        "services": [{"port": int(vs_port)}],
        "pool_ref": pool_ref,
        "application_profile_ref": "/api/applicationprofile?name=System-Secure-HTTP",
        "network_profile_ref": "/api/networkprofile?name=System-TCP-Proxy",
        "enabled": True
    }
    if se_group:
        vdata["se_group_ref"] = f"/api/serviceenginegroup?name={se_group}"

    vip_block = {
        "vip_id": "1",
        "enabled": True,
        "snat": True,
        "auto_allocate_ip": vs_ip.lower() == "auto",
        "auto_allocate_gateway": True
    }
    if vs_ip.lower() != "auto":
        vip_block["ip_address"] = {"addr": vs_ip, "type": "V4"}

    is_nsxt = cloud_name.lower() != "default-cloud"
    if vip_net:
        ref = build_network_ref(vip_net, cloud_uuid)
        if is_nsxt:
            vip_block["vip_network_ref"] = ref
        elif vip_subnet and vip_mask:
            vip_block["placement_networks"] = [{
                "subnet": {
                    "ip_addr": {"addr": vip_subnet, "type": "V4"},
                    "mask": int(vip_mask)
                },
                "network_ref": ref
            }]

    vdata["vip"] = [vip_block]

    if debug:
        logger.debug(f"[VS PAYLOAD] {vdata}")

    if dry:
        logger.info(f"[DRY-RUN] Would create VS '{vs_name}' (Cloud={cloud_name})")
        return vdata

    resp = api.post("virtualservice", data=vdata)
    if debug:
        logger.debug(f"[VS RESPONSE] {resp.status_code} → {resp.text}")

    if resp.status_code in (200, 201):
        logger.info(f"VS created: {vs_name} | Cloud={cloud_name}")
        return resp.json()

    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] VS '{vs_name}' failed due to network reference; retrying without vip_network_ref/placement_networks.")
        vip_block.pop("vip_network_ref", None)
        vip_block.pop("placement_networks", None)
        vdata["vip"] = [vip_block]
        resp2 = api.post("virtualservice", data=vdata)
        if debug:
            logger.debug(f"[VS RETRY RESPONSE] {resp2.status_code} → {resp2.text}")
        if resp2.status_code in (200, 201):
            logger.info(f"VS created (auto-placement): {vs_name}")
            return resp2.json()

    logger.error(f"VS create failed: {resp.text}")
    return None


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Bulk create VS & Pools in Avi with placement")
    p.add_argument("--controller", help="Avi Controller (prompted if not supplied)")
    p.add_argument("--username", help="Username (prompted if not supplied)")
    p.add_argument("--password", help="Password (prompted if not supplied)")
    p.add_argument("--tenant", default="admin", help="Tenant (default=admin)")
    p.add_argument("--csv", required=True, help="Input CSV path")
    p.add_argument("--log-dir", default="logs", help="Log directory (default=logs)")
    p.add_argument("--dry-run", action="store_true", help="Preview only, no creation")
    p.add_argument("--debug", action="store_true", help="Enable debug logging of full API payloads")
    a = p.parse_args()

    logger = setup_logger(a.log_dir, a.debug)
    logger.info(f"Input CSV: {a.csv}")
    if not a.controller:
        a.controller = input("Controller: ").strip()
    if not a.username:
        a.username = input("Username: ").strip()
    if not a.password:
        a.password = getpass.getpass("Password: ")

    api = ApiSession.get_session(a.controller, a.username, a.password, tenant=a.tenant)
    logger.info(f"Connected to '{a.controller}' as '{a.username}'")

    clouds = fetch_cloud_map(api, logger)
    nets = fetch_networks(api, logger)
    display_network_summary(clouds, nets, logger)
    if not os.path.exists(a.csv):
        logger.error(f"CSV '{a.csv}' not found.")
        sys.exit(1)

    with open(a.csv) as f:
        for r in csv.DictReader(f):
            vs = r.get("vs_name")
            pool = r.get("pool_name")
            cloud = r.get("cloud_name") or "Default-Cloud"
            cu = clouds.get(cloud)
            if not cu:
                logger.error(f"Cloud '{cloud}' not found on controller; skipping '{vs}'.")
                continue

            logger.info(f"\n[PROCESSING] VS='{vs}' Pool='{pool}' (Cloud={cloud})")
            pobj = create_pool(api, logger, pool,
                               r.get("pool_members", "").split(";"),
                               r.get("pool_network"), cu, cloud, a.dry_run, a.debug)
            if not pobj:
                logger.error(f"Skipping VS '{vs}' due to pool creation failure.")
                continue

            create_vs(api, logger, vs, r.get("vs_ip"), r.get("vs_port"), pool,
                      r.get("vip_network"), r.get("vip_subnet"), r.get("vip_mask"),
                      r.get("se_group"), cu, cloud, a.dry_run, a.debug)

    logger.info("\n✅ All processing complete.")
    if a.dry_run:
        logger.info("Dry-run complete — no changes applied.")


if __name__ == "__main__":
    main()
