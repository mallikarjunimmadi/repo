#!/usr/bin/env python3
"""
bulk_create_vs_full_placement.py
---------------------------------
Create multiple Virtual Services (VS) and Pools in NSX Advanced Load Balancer (Avi)
using a CSV file — includes VIP and Pool placement networks, SE group, SNAT, and auto-gateway.

Requirements:
    pip install avisdk
"""

import argparse
import csv
import datetime
import logging
import os
import sys
from avi.sdk.avi_api import ApiSession
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# ------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------
def setup_logger(log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"avi_vs_create_{ts}.log")

    logger = logging.getLogger("AviVSCreate")
    logger.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    )

    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.info(f"Logging initialized → {log_file}")
    return logger


# ------------------------------------------------------------
# Create Pool
# ------------------------------------------------------------
def create_pool(api, logger, pool_name, members, pool_network=None):
    try:
        existing = api.get_object_by_name("pool", pool_name)
        if existing:
            logger.warning(f"Pool '{pool_name}' already exists. Skipping creation.")
            return existing

        servers = []
        for m in members:
            ip, port = m.split(":")
            servers.append({"ip": {"addr": ip.strip(), "type": "V4"}, "port": int(port)})

        pool_data = {
            "name": pool_name,
            "lb_algorithm": "LB_ALGORITHM_ROUND_ROBIN",
            "servers": servers
        }

        if pool_network:
            pool_data["placement_networks"] = [{
                "network_ref": f"/api/network?name={pool_network}"
            }]

        resp = api.post("pool", data=pool_data)
        if resp.status_code in (200, 201):
            logger.info(f"Pool created: {pool_name}")
            return resp.json()
        else:
            logger.error(f"Failed to create pool '{pool_name}': {resp.text}")
            return None

    except Exception as e:
        logger.exception(f"Exception creating pool '{pool_name}': {e}")
        return None


# ------------------------------------------------------------
# Create Virtual Service
# ------------------------------------------------------------
def create_virtual_service(api, logger, vs_name, vs_ip, vs_port, pool_name,
                           vip_network=None, vip_subnet=None, vip_mask=None,
                           se_group=None):
    try:
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

        # Static VIP address
        if vs_ip.lower() != "auto":
            vip_block["ip_address"] = {"addr": vs_ip, "type": "V4"}

        # VIP placement
        if vip_network and vip_subnet and vip_mask:
            vip_block["placement_networks"] = [{
                "subnet": {
                    "ip_addr": {"addr": vip_subnet, "type": "V4"},
                    "mask": int(vip_mask)
                },
                "network_ref": f"/api/network?name={vip_network}"
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

        resp = api.post("virtualservice", data=vs_data)
        if resp.status_code in (200, 201):
            logger.info(f"VS created: {vs_name} | VIP={vs_ip} | SEGroup={se_group}")
            return resp.json()
        else:
            logger.error(f"Failed to create VS '{vs_name}': {resp.text}")
            return None

    except Exception as e:
        logger.exception(f"Exception creating VS '{vs_name}': {e}")
        return None


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Bulk create VS & Pools with placement in Avi")
    parser.add_argument("--controller", required=True, help="Avi Controller IP/FQDN")
    parser.add_argument("--username", required=True, help="Username for Avi login")
    parser.add_argument("--password", required=True, help="Password for Avi login")
    parser.add_argument("--tenant", default="admin", help="Tenant name (default=admin)")
    parser.add_argument("--csv", required=True, help="Path to CSV input")
    parser.add_argument("--log-dir", default="logs", help="Log directory (default=logs)")
    args = parser.parse_args()

    logger = setup_logger(args.log_dir)
    logger.info(f"Controller: {args.controller}, Tenant: {args.tenant}")
    logger.info(f"Input CSV: {args.csv}")

    try:
        api = ApiSession.get_session(
            controller=args.controller,
            username=args.username,
            password=args.password,
            tenant=args.tenant,
            verify=False
        )
        logger.info("Connected to Avi Controller successfully.")
    except Exception as e:
        logger.error(f"Failed to connect: {e}")
        sys.exit(1)

    if not os.path.exists(args.csv):
        logger.error(f"CSV '{args.csv}' not found.")
        sys.exit(1)

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

            logger.info(f"\n[PROCESSING] VS='{vs_name}' Pool='{pool_name}'")

            pool_obj = create_pool(api, logger, pool_name, members, pool_network)
            if not pool_obj:
                logger.error(f"Skipping VS '{vs_name}' due to pool creation failure.")
                continue

            create_virtual_service(
                api, logger,
                vs_name=vs_name,
                vs_ip=vs_ip,
                vs_port=vs_port,
                pool_name=pool_name,
                vip_network=vip_network,
                vip_subnet=vip_subnet,
                vip_mask=vip_mask,
                se_group=se_group
            )

    logger.info("\n✅ All VS and Pool creation tasks completed.")


if __name__ == "__main__":
    main()
