#!/usr/bin/env python3
"""
bulk_create_vs_full_placement_dryrun.py
---------------------------------------
Bulk-create Virtual Services, Pools, and VSVIPs with NSX-T compliance.

✅ CSV-driven configuration
✅ Auto-attach SSL Profile to VS + Pool for Secure-HTTP
✅ Health monitor(s) + application profile from CSV
✅ Pretty JSON debug logs
✅ Reuse existing VSVIP by IP/name
✅ Dry-run and Debug modes
✅ Generate CSV templates (--generate-sample-csv)
✅ Rich --help with usage examples
"""

import argparse, csv, datetime, logging, os, sys, getpass, json
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


# ---------- Helpers ----------
def pp(data): return json.dumps(data, indent=2, ensure_ascii=False)

def fetch_cloud_map(api, log):
    clouds={c["name"]:c["uuid"] for c in api.get("cloud").json().get("results",[])}
    log.info(f"Discovered Clouds: {', '.join(clouds.keys())}"); return clouds

def fetch_networks(api, log):
    nets={}
    for n in api.get("network").json().get("results",[]):
        cu=n.get("cloud_ref","").split("/")[-1]
        nets.setdefault(cu,[]).append(n)
    total=sum(len(v) for v in nets.values())
    log.info(f"Discovered {total} networks across {len(nets)} clouds.")
    return nets

def find_network_details(nets, cloud_uuid, name_or_uuid):
    for n in nets.get(cloud_uuid, []):
        if name_or_uuid in (n["name"], n["uuid"]):
            if n.get("configured_subnets"):
                s=n["configured_subnets"][0]
                return {
                    "uuid":n["uuid"],
                    "name":n["name"],
                    "subnet_addr":s["prefix"]["ip_addr"]["addr"],
                    "subnet_mask":s["prefix"]["mask"]
                }
    return None

def find_existing_vsvip_by_ip(api, vip_ip):
    resp = api.get("vsvip").json().get("results", [])
    for v in resp:
        for vip in v.get("vip", []):
            if vip.get("ip_address", {}).get("addr") == vip_ip:
                return v["name"]
    return None


# ---------- Pool ----------
def create_pool(api, log, name, members, net_name, cu, cn, dry, dbg, nets, health_monitor, app_prof):
    if api.get_object_by_name("pool", name):
        log.warning(f"Pool '{name}' exists. Skipping."); return True

    servers=[{"ip":{"addr":m.split(':')[0].strip(),"type":"V4"},
              "port":int(m.split(':')[1]) if ':' in m else 80}
             for m in members if m.strip()]

    data={"name":name,"cloud_ref":f"/api/cloud/{cu}",
          "lb_algorithm":"LB_ALGORITHM_ROUND_ROBIN","servers":servers}

    if health_monitor:
        hms = [f"/api/healthmonitor?name={hm.strip()}" for hm in health_monitor.split(",") if hm.strip()]
        data["health_monitor_refs"] = hms

    if app_prof == "System-Secure-HTTP":
        data["ssl_profile_ref"] = "/api/sslprofile?name=System-Standard-PFS"

    if net_name:
        nd=find_network_details(nets,cu,net_name)
        if nd:
            data["placement_networks"]=[{
                "network_ref":f"/api/network/{nd['uuid']}",
                "subnet":{
                    "ip_addr":{"addr":nd["subnet_addr"],"type":"V4"},
                    "mask":nd["subnet_mask"]
                }
            }]
        else:
            log.warning(f"Pool network '{net_name}' not found in cloud {cn}")

    if dbg: log.debug(f"[POOL PAYLOAD]\n{pp(data)}")
    if dry: log.info(f"[DRY-RUN] Would create Pool '{name}'"); return True

    r=api.post("pool",data=data)
    if dbg: log.debug(f"[POOL RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"Pool created: {name}"); return True
    log.error(f"Pool failed: {r.text}"); return False


# ---------- VSVIP ----------
def create_or_reuse_vsvip(api, log, name, vs_ip, vip_net, cu, cn, dry, dbg, nets):
    existing_by_ip = find_existing_vsvip_by_ip(api, vs_ip) if vs_ip.lower() != "auto" else None
    if existing_by_ip:
        log.info(f"Found existing VSVIP '{existing_by_ip}' for IP {vs_ip}. Reusing it.")
        return existing_by_ip

    existing_by_name = api.get_object_by_name("vsvip", name)
    if existing_by_name:
        log.info(f"Reusing existing VSVIP '{name}'"); return name

    nd=find_network_details(nets,cu,vip_net) if vip_net else None
    vip_block={
        "vip_id":"0","enabled":True,
        "auto_allocate_ip":vs_ip.lower()=="auto",
        "auto_allocate_floating_ip":False,
        "auto_allocate_ip_type":"V4_ONLY",
        "auto_allocate_gateway":True,
        "snat":True
    }
    if vs_ip.lower()!="auto":
        vip_block["ip_address"]={"addr":vs_ip,"type":"V4"}
        vip_block["prefix_length"]=32

    if nd:
        vip_block["placement_networks"]=[{
            "network_ref":f"/api/network/{nd['uuid']}",
            "subnet":{
                "ip_addr":{"addr":nd["subnet_addr"],"type":"V4"},
                "mask":nd["subnet_mask"]
            }
        }]

    data={"name":name,"cloud_ref":f"/api/cloud/{cu}","east_west_placement":False,"vip":[vip_block]}
    if dbg: log.debug(f"[VSVIP PAYLOAD]\n{pp(data)}")
    if dry: log.info(f"[DRY-RUN] Would create VSVIP '{name}'"); return name

    r=api.post("vsvip",data=data)
    if dbg: log.debug(f"[VSVIP RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"VSVIP created: {name}"); return name
    log.error(f"VSVIP failed: {r.text}"); return None


# ---------- VS ----------
def create_vs(api, log, vs, vs_ip, vs_port, pool, vip_net, se_group,
              vsvip_name, cu, cn, dry, dbg, nets, app_prof, ssl_prof):
    if api.get_object_by_name("virtualservice", vs):
        log.warning(f"VS '{vs}' exists. Skipping."); return True

    app_profile = app_prof or "System-L4-Application"
    ssl_profile = ssl_prof or ("System-Standard-PFS" if app_profile == "System-Secure-HTTP" else None)

    data={"name":vs,"cloud_ref":f"/api/cloud/{cu}",
          "services":[{"port":int(vs_port)}],
          "pool_ref":f"/api/pool?name={pool}",
          "application_profile_ref":f"/api/applicationprofile?name={app_profile}",
          "network_profile_ref":"/api/networkprofile?name=System-TCP-Proxy",
          "enabled":True}

    if se_group:
        data["se_group_ref"]=f"/api/serviceenginegroup?name={se_group}"
    if ssl_profile:
        data["ssl_profile_ref"]=f"/api/sslprofile?name={ssl_profile}"

    if cn.lower()!="default-cloud":
        vsvip_used = create_or_reuse_vsvip(api,log,vsvip_name,vs_ip,vip_net,cu,cn,dry,dbg,nets)
        if not vsvip_used:
            log.error(f"Skipping VS '{vs}' — VSVIP creation failed."); return False
        data["vsvip_ref"]=f"/api/vsvip?name={vsvip_used}"
    else:
        vip={"vip_id":"1","enabled":True,"auto_allocate_ip":vs_ip.lower()=="auto",
             "auto_allocate_gateway":True}
        if vs_ip.lower()!="auto": vip["ip_address"]={"addr":vs_ip,"type":"V4"}
        data["vip"]=[vip]

    if dbg: log.debug(f"[VS PAYLOAD]\n{pp(data)}")
    if dry: log.info(f"[DRY-RUN] Would create VS '{vs}'"); return True

    r=api.post("virtualservice",data=data)
    if dbg: log.debug(f"[VS RESPONSE] {r.status_code} → {r.text}")
    if r.status_code in (200,201): log.info(f"VS created: {vs}"); return True
    log.error(f"VS failed: {r.text}"); return False


# ---------- Generate Sample CSV ----------
def generate_sample_csv():
    ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname=f"avi_vs_sample_template_{ts}.csv"
    header=["vs_name","vs_ip","vs_port","pool_name","pool_members","vip_network",
            "pool_network","se_group","vsvip_name","application_profile",
            "health_monitor","ssl_profile","cloud_name"]
    sample=[
        ["tcp_vs1","10.10.10.11","1521","ora_pool","10.10.20.11:1521;10.10.20.12:1521",
         "mum01-1-dmz-vlan203","m01-avi-se-b-prod-1456","Internal-SE-Group","","System-L4-Application","System-TCP","","NSX-T-UAT"],
        ["http_vs1","10.10.10.12","80","web_pool","10.10.20.21:80;10.10.20.22:80",
         "mum01-1-dmz-vlan203","m01-avi-se-b-prod-1456","Internal-SE-Group","","System-HTTP","System-HTTP","","NSX-T-UAT"],
        ["https_vs1","10.10.10.13","443","secure_pool","10.10.20.31:443;10.10.20.32:443",
         "mum01-1-dmz-vlan203","m01-avi-se-b-prod-1456","Internal-SE-Group","","System-Secure-HTTP","System-HTTPS","","NSX-T-UAT"]
    ]
    with open(fname,"w",newline="") as f:
        csv.writer(f).writerows([header]+sample)
    print(f"✅ Sample CSV template generated: {fname}")


# ---------- Main ----------
def main():
    examples = """
Examples:
  # 1️⃣ Generate a ready-to-fill sample CSV template
  python3 bulk_create_vs_full_placement_dryrun.py --generate-sample-csv

  # 2️⃣ Dry-run (no changes, only payloads logged)
  python3 bulk_create_vs_full_placement_dryrun.py --controller m00avientuat --csv my_vs_list.csv --dry-run

  # 3️⃣ Actual creation (execute API calls)
  python3 bulk_create_vs_full_placement_dryrun.py --controller m00avientuat --csv my_vs_list.csv

  # 4️⃣ Enable full debug logging (print payloads & API responses)
  python3 bulk_create_vs_full_placement_dryrun.py --controller m00avientuat --csv my_vs_list.csv --debug

  # 5️⃣ Combined dry-run + debug (safe validation mode)
  python3 bulk_create_vs_full_placement_dryrun.py --controller m00avientuat --csv my_vs_list.csv --dry-run --debug
"""
    p=argparse.ArgumentParser(
        description="Bulk-create NSX-T compatible Virtual Services, Pools, and VSVIPs from a CSV input.",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    p.add_argument("--controller", help="Avi Controller hostname or IP (mandatory for create mode)")
    p.add_argument("--username", help="Avi username")
    p.add_argument("--password", help="Avi password (prompted if omitted)")
    p.add_argument("--tenant", default="admin", help="Avi tenant name (default: admin)")
    p.add_argument("--csv", help="Path to CSV file containing VS and Pool definitions")
    p.add_argument("--log-dir", default="logs", help="Directory to store log files (default: ./logs)")
    p.add_argument("--dry-run", action="store_true", help="Run in validation-only mode without API calls")
    p.add_argument("--debug", action="store_true", help="Enable detailed debug logging (payloads, responses)")
    p.add_argument("--generate-sample-csv", action="store_true",
                   help="Generate a sample CSV template and exit (no other args allowed)")
    a=p.parse_args()

    # Exclusive mode for --generate-sample-csv
    if a.generate_sample_csv:
        if any([a.controller, a.username, a.password, a.csv, a.dry_run, a.debug]):
            print("❌ When using --generate-sample-csv, no other arguments are allowed.")
            sys.exit(1)
        generate_sample_csv()
        sys.exit(0)

    log=setup_logger(a.log_dir,a.debug)
    if not a.controller: a.controller=input("Controller: ").strip()
    if not a.username: a.username=input("Username: ").strip()
    if not a.password: a.password=getpass.getpass("Password: ")

    if not a.csv:
        log.error("Missing --csv argument."); sys.exit(1)

    api=ApiSession.get_session(a.controller,a.username,a.password,tenant=a.tenant)
    log.info(f"Connected to '{a.controller}' as '{a.username}'")

    clouds=fetch_cloud_map(api,log); nets=fetch_networks(api,log)

    if not os.path.exists(a.csv): log.error("CSV not found."); sys.exit(1)
    with open(a.csv) as f:
        for r in csv.DictReader(f):
            vs, pool = r["vs_name"], r["pool_name"]
            cn = r.get("cloud_name") or "Default-Cloud"
            cu = clouds.get(cn)
            if not cu: log.error(f"Cloud '{cn}' not found; skipping '{vs}'."); continue
            vsvip_name = r.get("vsvip_name") or f"{vs}_vsvip"
            log.info(f"\n[PROCESSING] VS='{vs}' Pool='{pool}' VSVIP='{vsvip_name}' (Cloud={cn})")

            ok=create_pool(api,log,pool,r.get("pool_members","").split(";"),
                           r.get("pool_network"),cu,cn,a.dry_run,a.debug,nets,
                           r.get("health_monitor"),r.get("application_profile"))
            if not ok: continue
            create_vs(api,log,vs,r.get("vs_ip"),r.get("vs_port"),pool,
                      r.get("vip_network"),r.get("se_group"),vsvip_name,
                      cu,cn,a.dry_run,a.debug,nets,
                      r.get("application_profile"),r.get("ssl_profile"))
    log.info("\n✅ All processing complete.")


if __name__=="__main__": main()
