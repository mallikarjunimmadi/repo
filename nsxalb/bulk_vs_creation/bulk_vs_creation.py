#!/usr/bin/env python3
"""
bulk_create_vs_full_placement_dryrun.py — Cloud-aware Avi automation
Now ensures Pool/VS/VSVIP are created in the CSV-specified cloud.
"""

import argparse, csv, datetime, logging, os, sys, getpass
from avi.sdk.avi_api import ApiSession
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)


# ---------- Logging ----------
def setup_logger(log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"avi_vs_create_{ts}.log")
    logger = logging.getLogger("AviVSCreate")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout); ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    fh = logging.FileHandler(log_file); fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s","%Y-%m-%d %H:%M:%S"))
    logger.addHandler(ch); logger.addHandler(fh)
    logger.info(f"Logging initialized → {log_file}")
    return logger


# ---------- Discovery helpers ----------
def fetch_cloud_map(api, logger):
    try:
        clouds = {c["name"]: c["uuid"] for c in api.get("cloud").json().get("results", [])}
        logger.info(f"Discovered Clouds: {', '.join(clouds.keys())}")
        return clouds
    except Exception as e:
        logger.error(f"Failed to fetch clouds: {e}"); return {}

def fetch_networks(api, logger):
    nets_by_uuid = {}
    try:
        for net in api.get("network").json().get("results", []):
            cloud_uuid = net.get("cloud_ref","").split("/")[-1]
            nets_by_uuid.setdefault(cloud_uuid, []).append(net["name"])
        logger.info(f"Discovered {sum(len(v) for v in nets_by_uuid.values())} networks across {len(nets_by_uuid)} clouds.")
        return nets_by_uuid
    except Exception as e:
        logger.error(f"Failed to fetch networks: {e}"); return {}

def display_network_summary(cloud_map, nets_by_uuid, logger):
    logger.info("\n📋 Networks available per Cloud:")
    rev = {v:k for k,v in cloud_map.items()}
    for cu,names in nets_by_uuid.items():
        cname = rev.get(cu, cu)
        logger.info(f"  → {cname} ({len(names)} networks)")
        for n in sorted(names): logger.info(f"     - {n}")


# ---------- Utility ----------
def build_network_ref(net, cloud_uuid):
    if not net: return None
    return f"/api/network/{net}" if net.startswith("network-") else f"/api/network?name={net}&cloud_ref=/api/cloud/{cloud_uuid}"


# ---------- Create Pool ----------
def create_pool(api, logger, name, members, pool_network, cloud_uuid, cloud_name, dry):
    existing = api.get_object_by_name("pool", name)
    if existing: logger.warning(f"Pool '{name}' exists. Skipping."); return existing
    servers=[{"ip":{"addr":m.split(':')[0].strip(),"type":"V4"},"port":int(m.split(':')[1]) if ':' in m else 80}
             for m in members if m.strip()]
    pdata={"name":name,"cloud_ref":f"/api/cloud/{cloud_uuid}","lb_algorithm":"LB_ALGORITHM_ROUND_ROBIN","servers":servers}
    if pool_network:
        ref=build_network_ref(pool_network,cloud_uuid)
        if ref: pdata["placement_networks"]=[{"network_ref":ref}]
    if dry: logger.info(f"[DRY-RUN] Would create Pool '{name}' in {cloud_name}."); return pdata

    resp=api.post("pool",data=pdata)
    if resp.status_code in (200,201): logger.info(f"Pool created: {name} ({cloud_name})"); return resp.json()
    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] Pool '{name}' failed due to network object; retrying without placement.")
        pdata.pop("placement_networks",None)
        r2=api.post("pool",data=pdata)
        if r2.status_code in (200,201): logger.info(f"Pool created (auto-placement): {name}"); return r2.json()
    logger.error(f"Pool create failed: {resp.text}"); return None


# ---------- Create VS ----------
def create_vs(api, logger, vs_name, vs_ip, vs_port, pool_name,
              vip_net, vip_subnet, vip_mask, se_group, cloud_uuid, cloud_name, dry):
    existing=api.get_object_by_name("virtualservice",vs_name)
    if existing: logger.warning(f"VS '{vs_name}' exists. Skipping."); return existing
    pool_ref=f"/api/pool?name={pool_name}"
    vip={"vip_id":"1","enabled":True,"snat":True,"auto_allocate_ip":vs_ip.lower()=="auto",
         "auto_allocate_floating_ip":False,"avi_allocated_vip":vs_ip.lower()=="auto",
         "auto_allocate_ip_type":"V4_ONLY","auto_allocate_gateway":True}
    if vs_ip.lower()!="auto": vip["ip_address"]={"addr":vs_ip,"type":"V4"}
    ref=build_network_ref(vip_net,cloud_uuid)
    if ref and vip_subnet and vip_mask:
        vip["placement_networks"]=[{"subnet":{"ip_addr":{"addr":vip_subnet,"type":"V4"},"mask":int(vip_mask)},
                                   "network_ref":ref}]
    vdata={"name":vs_name,"cloud_ref":f"/api/cloud/{cloud_uuid}","vip":[vip],
           "services":[{"port":int(vs_port)}],"pool_ref":pool_ref,
           "application_profile_ref":"/api/applicationprofile?name=System-Secure-HTTP",
           "network_profile_ref":"/api/networkprofile?name=System-TCP-Proxy","enabled":True}
    if se_group: vdata["se_group_ref"]=f"/api/serviceenginegroup?name={se_group}"
    if dry: logger.info(f"[DRY-RUN] Would create VS '{vs_name}' (Cloud={cloud_name})."); return vdata

    resp=api.post("virtualservice",data=vdata)
    if resp.status_code in (200,201):
        logger.info(f"VS created: {vs_name} | Cloud={cloud_name}"); return resp.json()
    if "network object not found" in resp.text.lower():
        logger.warning(f"[RETRY] VS '{vs_name}' failed due to network object; retrying without placement.")
        vip.pop("placement_networks",None); vdata["vip"]=[vip]
        r2=api.post("virtualservice",data=vdata)
        if r2.status_code in (200,201): logger.info(f"VS created (auto-placement): {vs_name}"); return r2.json()
    logger.error(f"VS create failed: {resp.text}"); return None


# ---------- Main ----------
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--controller"); p.add_argument("--username"); p.add_argument("--password")
    p.add_argument("--tenant",default="admin"); p.add_argument("--csv",required=True)
    p.add_argument("--log-dir",default="logs"); p.add_argument("--dry-run",action="store_true")
    a=p.parse_args()

    log=setup_logger(a.log_dir); log.info(f"Input CSV: {a.csv}")
    if not a.controller: a.controller=input("Controller: ").strip()
    if not a.username: a.username=input("Username: ").strip()
    if not a.password: a.password=getpass.getpass("Password: ")

    api=ApiSession.get_session(a.controller,a.username,a.password,tenant=a.tenant)
    log.info(f"Connected to '{a.controller}' as '{a.username}'")

    clouds=fetch_cloud_map(api,log); nets=fetch_networks(api,log); display_network_summary(clouds,nets,log)
    if not os.path.exists(a.csv): log.error("CSV missing."); sys.exit(1)

    with open(a.csv) as f:
        for r in csv.DictReader(f):
            vs=r.get("vs_name"); pool=r.get("pool_name"); vip_net=r.get("vip_network")
            pool_net=r.get("pool_network"); cloud=r.get("cloud_name") or "Default-Cloud"
            cu=clouds.get(cloud)
            log.info(f"\n[PROCESSING] VS='{vs}' Pool='{pool}' (Cloud={cloud})")
            pobj=create_pool(api,log,pool,r.get("pool_members","").split(";"),
                             pool_net,cu,cloud,a.dry_run)
            if not pobj: continue
            create_vs(api,log,vs,r.get("vs_ip"),r.get("vs_port"),pool,
                      vip_net,r.get("vip_subnet"),r.get("vip_mask"),
                      r.get("se_group"),cu,cloud,a.dry_run)
    log.info("\n✅ All processing complete.")


if __name__=="__main__": main()
