#!/usr/bin/env python3
"""
bulk_create_vs_full_placement_dryrun.py — NSX-T / vCenter aware

Adds proper VSVIP object creation for NSX-T Clouds.
"""

import argparse, csv, datetime, logging, os, sys, getpass
from avi.sdk.avi_api import ApiSession
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# ---------- Logger ----------
def setup_logger(log_dir="logs", debug=False):
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"avi_vs_create_{ts}.log")
    log = logging.getLogger("AviVSCreate"); log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout); ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    fh = logging.FileHandler(log_file); fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s","%Y-%m-%d %H:%M:%S"))
    log.addHandler(ch); log.addHandler(fh)
    log.info(f"Logging initialized → {log_file}")
    if debug: log.info("Debug mode enabled — full payloads/responses logged.")
    return log


# ---------- Discovery ----------
def fetch_cloud_map(api, log):
    clouds={c["name"]:c["uuid"] for c in api.get("cloud").json().get("results",[])}
    log.info(f"Discovered Clouds: {', '.join(clouds.keys())}"); return clouds

def fetch_networks(api, log):
    nets={}; r=api.get("network").json().get("results",[])
    for n in r:
        cu=n.get("cloud_ref","").split("/")[-1]; nets.setdefault(cu,[]).append(n["name"])
    log.info(f"Discovered {sum(len(v) for v in nets.values())} networks across {len(nets)} clouds.")
    return nets

def display_network_summary(clouds,nets,log):
    log.info("\n📋 Networks available per Cloud:")
    rev={v:k for k,v in clouds.items()}
    for cu,names in nets.items():
        cname=rev.get(cu,cu)
        log.info(f"  → {cname} ({len(names)} networks)")
        for n in sorted(names): log.info(f"     - {n}")

def build_network_ref(net,cloud_uuid):
    if not net: return None
    return f"/api/network/{net}" if net.startswith("network-") else f"/api/network?name={net}&cloud_ref=/api/cloud/{cloud_uuid}"


# ---------- Pool ----------
def create_pool(api,log,name,members,net,cu,cn,dry,dbg):
    if api.get_object_by_name("pool",name):
        log.warning(f"Pool '{name}' exists. Skipping."); return True
    servers=[{"ip":{"addr":m.split(':')[0].strip(),"type":"V4"},"port":int(m.split(':')[1]) if ':' in m else 80}
             for m in members if m.strip()]
    data={"name":name,"cloud_ref":f"/api/cloud/{cu}","lb_algorithm":"LB_ALGORITHM_ROUND_ROBIN","servers":servers}
    if net: data["placement_networks"]=[{"network_ref":build_network_ref(net,cu)}]
    if dbg: log.debug(f"[POOL PAYLOAD] {data}")
    if dry: log.info(f"[DRY-RUN] Would create Pool '{name}' ({cn})"); return True
    r=api.post("pool",data=data)
    if dbg: log.debug(f"[POOL RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"Pool created: {name} ({cn})"); return True
    if "network object not found" in r.text.lower():
        data.pop("placement_networks",None); r2=api.post("pool",data=data)
        if dbg: log.debug(f"[POOL RETRY] {r2.status_code} → {r2.text}")
        if r2.status_code in (200,201): log.info(f"Pool created (auto-placement): {name}"); return True
    log.error(f"Pool failed: {r.text}"); return False


# ---------- VSVIP ----------
def create_vsvip(api,log,name,vs_ip,vip_net,cu,cn,dry,dbg):
    if api.get_object_by_name("vsvip",name):
        log.warning(f"VSVIP '{name}' exists. Skipping."); return True
    ref=build_network_ref(vip_net,cu) if vip_net else None
    vsvip={
        "name":name,
        "cloud_ref":f"/api/cloud/{cu}",
        "vip":[{
            "ip_address": {"addr": vs_ip, "type": "V4"},
            "enabled": True,
            "auto_allocate_ip": vs_ip.lower()=="auto",
            "auto_allocate_gateway": True
        }]
    }
    if ref: vsvip["vip"][0]["vip_network_ref"]=ref
    if dbg: log.debug(f"[VSVIP PAYLOAD] {vsvip}")
    if dry: log.info(f"[DRY-RUN] Would create VSVIP '{name}'"); return True
    r=api.post("vsvip",data=vsvip)
    if dbg: log.debug(f"[VSVIP RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"VSVIP created: {name} ({cn})"); return True
    if "network object not found" in r.text.lower():
        vsvip["vip"][0].pop("vip_network_ref",None); r2=api.post("vsvip",data=vsvip)
        if dbg: log.debug(f"[VSVIP RETRY] {r2.status_code} → {r2.text}")
        if r2.status_code in (200,201): log.info(f"VSVIP auto-placement: {name}"); return True
    log.error(f"VSVIP failed: {r.text}"); return False


# ---------- VS ----------
def create_vs(api,log,vs,vs_ip,vs_port,pool,vip_net,se_group,cu,cn,dry,dbg):
    if api.get_object_by_name("virtualservice",vs):
        log.warning(f"VS '{vs}' exists. Skipping."); return True
    data={"name":vs,"cloud_ref":f"/api/cloud/{cu}",
          "services":[{"port":int(vs_port)}],
          "pool_ref":f"/api/pool?name={pool}",
          "application_profile_ref":"/api/applicationprofile?name=System-Secure-HTTP",
          "network_profile_ref":"/api/networkprofile?name=System-TCP-Proxy",
          "enabled":True}
    if se_group: data["se_group_ref"]=f"/api/serviceenginegroup?name={se_group}"

    # NSX-T => separate VSVIP
    if cn.lower()!="default-cloud":
        vsvip_name=f"{vs}_vsvip"
        if not create_vsvip(api,log,vsvip_name,vs_ip,vip_net,cu,cn,dry,dbg):
            log.error(f"Skipping VS '{vs}' — VSVIP creation failed."); return False
        data["vsvip_ref"]=f"/api/vsvip?name={vsvip_name}"
    else:
        # Legacy inline for vCenter
        vip={"vip_id":"1","enabled":True,"snat":True,"auto_allocate_ip":vs_ip.lower()=="auto",
             "auto_allocate_gateway":True}
        if vs_ip.lower()!="auto": vip["ip_address"]={"addr":vs_ip,"type":"V4"}
        ref=build_network_ref(vip_net,cu)
        if ref: vip["vip_network_ref"]=ref
        data["vip"]=[vip]

    if dbg: log.debug(f"[VS PAYLOAD] {data}")
    if dry: log.info(f"[DRY-RUN] Would create VS '{vs}' ({cn})"); return True
    r=api.post("virtualservice",data=data)
    if dbg: log.debug(f"[VS RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"VS created: {vs} ({cn})"); return True
    log.error(f"VS failed: {r.text}"); return False


# ---------- Main ----------
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--controller"); p.add_argument("--username"); p.add_argument("--password")
    p.add_argument("--tenant",default="admin"); p.add_argument("--csv",required=True)
    p.add_argument("--log-dir",default="logs"); p.add_argument("--dry-run",action="store_true")
    p.add_argument("--debug",action="store_true")
    a=p.parse_args()

    log=setup_logger(a.log_dir,a.debug)
    if not a.controller: a.controller=input("Controller: ").strip()
    if not a.username: a.username=input("Username: ").strip()
    if not a.password: a.password=getpass.getpass("Password: ")

    api=ApiSession.get_session(a.controller,a.username,a.password,tenant=a.tenant)
    log.info(f"Connected to '{a.controller}' as '{a.username}'")

    clouds=fetch_cloud_map(api,log); nets=fetch_networks(api,log); display_network_summary(clouds,nets,log)
    if not os.path.exists(a.csv): log.error("CSV not found."); sys.exit(1)

    with open(a.csv) as f:
        for r in csv.DictReader(f):
            vs, pool = r["vs_name"], r["pool_name"]
            cn = r.get("cloud_name") or "Default-Cloud"
            cu = clouds.get(cn)
            if not cu: log.error(f"Cloud '{cn}' not found; skipping '{vs}'."); continue
            log.info(f"\n[PROCESSING] VS='{vs}' Pool='{pool}' (Cloud={cn})")

            ok=create_pool(api,log,pool,r.get("pool_members","").split(";"),
                           r.get("pool_network"),cu,cn,a.dry_run,a.debug)
            if not ok: continue
            create_vs(api,log,vs,r.get("vs_ip"),r.get("vs_port"),pool,
                      r.get("vip_network"),r.get("se_group"),cu,cn,a.dry_run,a.debug)
    log.info("\n✅ All processing complete.")


if __name__=="__main__": main()
