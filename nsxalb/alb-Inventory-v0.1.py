import os
import requests
import json
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode
import urllib3
import argparse
import configparser

# Disable SSL certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables (will be set from config.ini in main)
AVI_VERSION = None
API_STEP = None
API_LIMIT = None
metrics = None  # This will hold the final list of metrics to use

# --- LOGGING SETUP ---
def configure_logging(debug_mode, log_file_path):
    """Configures the logging system."""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s: %(levelname)s: %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler()
        ]
    )
    log(f"Logging configured. Level: {'DEBUG' if debug_mode else 'INFO'}", "info")

def log(message, level="info"):
    """Wrapper for logging messages."""
    if level == "info":
        logging.info(message)
    elif level == "debug":
        logging.debug(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
    else:
        logging.info(message)

# --- UTILITY FUNCTIONS ---
def validate_step(step):
    """Ensures the API step value is valid for AVI."""
    if step < 300:
        log("Step too low. Adjusting to 300.", "debug")
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
        log(f"Step not multiple of 300. Adjusting to {step}.", "debug")
    return step

def convert_to_mbps(bits_per_second):
    """Converts bits per second to MBPS."""
    if isinstance(bits_per_second, (int, float)):
        return round(bits_per_second / 1048576, 2)
    return "N/A"

def quote_field(field):
    """Quotes a CSV field if it contains commas to handle special characters."""
    field_str = str(field) if field is not None else ""
    escaped_field = field_str.replace('"', '""')
    return f'"{escaped_field}"' if ',' in escaped_field or '"' in escaped_field else escaped_field

# --- AVI API INTERACTION FUNCTIONS ---
def avi_login(controller, avi_user, avi_pass):
    """Attempts to log in to the AVI controller and retrieve session/CSRF tokens."""
    url = f"https://{controller}/login"
    log(f"Attempting login to {controller} as {avi_user}.", "info")
    try:
        response = requests.post(url, data={'username': avi_user, 'password': avi_pass}, verify=False, timeout=10)
        if response.status_code != 200:
            log(f"Login failed for {controller}. Status: {response.status_code} - {response.text}", "error")
            return None, None
        cookies = response.cookies.get_dict()
        sid = cookies.get('avi-sessionid')
        csrft = cookies.get('csrftoken')
        if not sid or not csrft:
            log(f"Missing session or CSRF token from {controller} after login.", "error")
            return None, None
        log(f"Login successful for {controller}.", "info")
        return sid, csrft
    except requests.exceptions.RequestException as e:
        log(f"Login error for {controller}: {e}", "error")
        return None, None

def get_all_service_engines(controller, sid, csrft):
    """Fetches all Service Engines for name lookup."""
    headers = {
        "X-Avi-Tenant": "admin", "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }
    se_name_lookup, url = {}, f"https://{controller}/api/serviceengine-inventory/"
    log(f"Starting fetch of Service Engines for name lookup from {controller}.", "info")
    try:
        se_count = 0
        while url:
            r = requests.get(url, headers=headers, verify=False, timeout=30)
            if r.status_code != 200:
                log(f"Failed to fetch SEs for name lookup from {controller}. Status: {r.status_code} - {r.text}", "error")
                return se_name_lookup
            response_data = r.json()

            # Add detailed logging to inspect the response data
            #log(f"Response data for SE lookup: {json.dumps(response_data, indent=4)}", "debug")

            for se in response_data.get("results", []):
                se_uuid = se.get("uuid")
                if se_uuid:
                    se_name = se.get("config", {}).get("name", "null")  # Correctly access the name from the config
                    se_name_lookup[se_uuid] = se_name
                    se_count += 1
                    log(f"Discovered SE for name lookup: UUID={se_uuid}, Name={se_name}", "debug")
                else:
                    log(f"Found SE entry without UUID in serviceengine-inventory from {controller}. Skipping for name lookup.", "warning")
            url = response_data.get("next")
        log(f"Successfully fetched names for {se_count} Service Engines from {controller}.", "info")
    except Exception as e:
        log(f"SE name lookup fetch error on {controller}: {e}", "error")
    return se_name_lookup

def get_vs_inventory(controller, sid, csrft, se_name_lookup):
    """Fetches Virtual Service inventory and correlates with SEs, including both IPv4 and IPv6 VIPs."""
    headers = {
        "X-Avi-Tenant": "admin", "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }
    url = f"https://{controller}/api/virtualservice-inventory/"
    vs_list = []
    log(f"Starting fetch of Virtual Service inventory from {controller}.", "info")

    try:
        vs_count = 0
        while url:
            r = requests.get(url, headers=headers, verify=False, timeout=30)
            if r.status_code != 200:
                log(f"VS inventory fetch failed from {controller}. Status: {r.status_code} - {r.text}", "error")
                return vs_list
            response_data = r.json()
            for item in response_data.get("results", []):
                vs_count += 1
                cfg, rt = item.get("config", {}), item.get("runtime", {})
                vs_uuid, vs_name = cfg.get("uuid", "null"), cfg.get("name", "null")
                log(f"Processing VS: {vs_name} (UUID: {vs_uuid})", "debug")

                # Extract VS Information
                vs_ip, vs_ip_type = [], []  # Now lists to store both IPv4 and IPv6 addresses
                vs_enabled = cfg.get("enabled", False)
                ssl_enabled = "null"
                traffic_enabled = cfg.get("traffic_enabled", False)

                # Extract VIP and SE information
                if cfg.get("vip"):
                    for vip_info in cfg["vip"]:
                        # Handle IPv4 address
                        if 'ip_address' in vip_info:
                            ip = vip_info['ip_address'].get('addr', 'null')
                            ip_type = vip_info['ip_address'].get('type', 'null')
                            vs_ip.append(ip)
                            vs_ip_type.append(ip_type)
                            log(f"Found IPv4 address {ip} of type {ip_type} for VS {vs_name} (UUID: {vs_uuid})", "debug")
                        # Handle IPv6 address
                        if 'ip6_address' in vip_info:
                            ip6 = vip_info['ip6_address'].get('addr', 'null')
                            ip6_type = vip_info['ip6_address'].get('type', 'null')
                            vs_ip.append(ip6)
                            vs_ip_type.append(ip6_type)
                            log(f"Found IPv6 address {ip6} of type {ip6_type} for VS {vs_name} (UUID: {vs_uuid})", "debug")

                # Format the IPs properly
                vs_ip_str = ";".join(vs_ip) if vs_ip else 'null'  # Join IPs with semicolon if multiple
                vs_ip_type_str = ";".join(vs_ip_type) if vs_ip_type else 'null'  # Join IP types with semicolon

                # Extract runtime information
                state = rt.get("oper_status", {}).get("state", "null")
                reason = rt.get("oper_status", {}).get("reason", "null")
                port = "null"
                if cfg.get("services"):
                    first_service = cfg["services"][0]
                    port = first_service.get("port", "null")

                # Extract SE information from the vip_summary
                primary_uuid = primary_name = primary_ip = "null"
                secondary_uuid = secondary_name = secondary_ip = "null"

                if rt.get("vip_summary") and isinstance(rt["vip_summary"], list):
                    for vip_summary in rt["vip_summary"]:
                        if vip_summary.get("service_engine") and isinstance(vip_summary["service_engine"], list):
                            for se in vip_summary["service_engine"]:
                                se_uuid = se.get("uuid")
                                if se_uuid:
                                    se_name = se_name_lookup.get(se_uuid, "null")
                                    se_mgmt_ip = se.get("mgmt_ip", {}).get("addr", "null")

                                    # Identify primary SE
                                    if se.get("primary"):
                                        primary_uuid = se_uuid
                                        primary_name = se_name
                                        primary_ip = se_mgmt_ip
                                        log(f"VS {vs_name}: Primary SE (from VS runtime) - UUID: {primary_uuid}, Name: {primary_name}, Mgmt IP: {primary_ip}", "debug")
                                    # Identify secondary SE
                                    elif se.get("standby"):
                                        secondary_uuid = se_uuid
                                        secondary_name = se_name
                                        secondary_ip = se_mgmt_ip
                                        log(f"VS {vs_name}: Secondary SE (from VS runtime) - UUID: {secondary_uuid}, Name: {secondary_name}, Mgmt IP: {secondary_ip}", "debug")

                vs_list.append((
                    vs_uuid, vs_name, vs_ip_str, vs_ip_type_str, vs_enabled,traffic_enabled,ssl_enabled, state, reason, port,
                    primary_uuid, primary_name, primary_ip, secondary_uuid, secondary_name, secondary_ip
                ))
            url = response_data.get("next")
        log(f"Successfully fetched {vs_count} Virtual Services from {controller}.", "info")
    except Exception as e:
        log(f"VS inventory error on {controller}: {e}", "error")
    return vs_list

def fetch_performance_metrics(controller, vs_data, sid, csrft, csv_file):
    """Fetches performance metrics for a specific Virtual Service and appends to CSV."""
    (vs_uuid, vs_name, vs_ip, vs_ip_type, vs_enabled,traffic_enabled,ssl_enabled, state, reason, port,
     primary_uuid, primary_name, primary_ip, secondary_uuid, secondary_name, secondary_ip) = vs_data
    
    step = validate_step(API_STEP)  # Use global API_STEP
    
    params = {
        "metric_id": metrics,  # Use global metrics
        "limit": API_LIMIT,    # Use global API_LIMIT
        "step": step
    }
    url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/?" + urlencode(params)

    headers = {
        "X-Avi-Tenant": "admin", "X-Avi-Version": AVI_VERSION,  # Use global AVI_VERSION
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }
    log(f"Fetching metrics for VS: {vs_name} (UUID: {vs_uuid}) from {controller}.", "debug")
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=30)
        if r.status_code != 200:
            log(f"Metrics fetch failed for {vs_name} (UUID: {vs_uuid}). Status: {r.status_code} - {r.text}", "error")
            metrics_values = ["N/A"] * len(metrics.split(','))
        else:
            data = r.json()
            metrics_values = []
            for metric in metrics.split(','):
                s = next((s for s in data.get("series", []) if s.get("header", {}).get("name") == metric), None)
                value = s.get("data", [{}])[0].get("value", "N/A") if s and s.get("data") else "N/A"
                if metric == "l4_client.avg_bandwidth":
                    value = convert_to_mbps(value)
                metrics_values.append(value)

        with open(csv_file, 'a') as f:
            f.write(f"{controller},{quote_field(vs_name)},{vs_uuid},{vs_ip},{vs_ip_type},{vs_enabled},{traffic_enabled},{ssl_enabled},"
                    f"{state},{quote_field(reason)},{port},"
                    f"{primary_uuid},{quote_field(primary_name)},{primary_ip},{secondary_uuid},{quote_field(secondary_name)},{secondary_ip},"
                    f"{','.join(map(str, metrics_values))}\n")
        log(f"Successfully wrote metrics for VS: {vs_name} (UUID: {vs_uuid}) to CSV.", "debug")
    except Exception as e:
        log(f"Metric fetch or write error for VS {vs_name} (UUID: {vs_uuid}): {e}", "error")

def process_virtual_service(controller, sid, csrft, csv_file, vs_list):
    """Processes a list of Virtual Services for a given controller."""
    log(f"Initiating processing for {len(vs_list)} Virtual Services for controller {controller}.", "info")
    for vs in vs_list:
        fetch_performance_metrics(controller, vs, sid, csrft, csv_file)
    log(f"Finished processing Virtual Services for controller {controller}.", "info")

def process_controller(controller_name, csv_file, default_user, default_pass, controller_credentials):
    """Handles the full data collection for a single AVI controller."""
    user, pwd = controller_credentials.get(controller_name, (default_user, default_pass))
    log(f"Starting processing for controller: {controller_name}", "info")
    sid, csrft = avi_login(controller_name, user, pwd)
    if not sid or not csrft:
        log(f"Skipping {controller_name} due to login failure.", "error")
        return
    
    # Step 1: Get SE names from serviceengine-inventory
    se_name_lookup = get_all_service_engines(controller_name, sid, csrft)
    if not se_name_lookup:
        log(f"Warning: No Service Engine names found or fetched for {controller_name}. SE names in CSV might be 'null'.", "warning")
    
    # Step 2: Get VS inventory and correlate with SE names and get SE mgmt_ip from VS runtime
    vs_list = get_vs_inventory(controller_name, sid, csrft, se_name_lookup)
    if vs_list:
        process_virtual_service(controller_name, sid, csrft, csv_file, vs_list)
    else:
        log(f"No Virtual Services found for {controller_name}.", "info")
    log(f"Finished processing for controller: {controller_name}", "info")

# --- MAIN SCRIPT EXECUTION ---
def main(args):
    # Declare global variables to be assigned values from config.ini
    global AVI_VERSION, API_STEP, API_LIMIT, metrics

    # Read configuration from config.ini
    config = configparser.ConfigParser()
    config_file_path = '/home/imallikarjun/scripts/nsxalb/config.ini'

    if not os.path.exists(config_file_path):
        print(f"Error: '{config_file_path}' not found. Please create it with controller credentials and settings.")
        print("Exiting script.")
        return

    try:
        config.read(config_file_path)

        # 1. Read DEFAULT credentials
        default_avi_user = config.get('DEFAULT', 'avi_user', fallback="admin")
        default_avi_pass = config.get('DEFAULT', 'avi_pass', fallback="VMware1!VMware1!")

        # 2. Read SETTINGS
        # Global variables assigned here
        AVI_VERSION = config.get('SETTINGS', 'avi_version', fallback="22.1.4")
        API_STEP = config.getint('SETTINGS', 'api_step', fallback=21600)
        API_LIMIT = config.getint('SETTINGS', 'api_limit', fallback=1)
        
        metrics_list_from_config = config.get('SETTINGS', 'metrics_list', fallback="").strip()
        default_metrics_from_config = config.get('SETTINGS', 'default_metrics', 
                                                 fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
        
        # Determine actual metrics to use (command-line takes precedence)
        if args.metrics:
            metrics = args.metrics
        else:
            metrics = metrics_list_from_config if metrics_list_from_config else default_metrics_from_config
            if not metrics:
                 metrics = "l4_client.avg_bandwidth" # Final fallback if config and cmd-line are empty

        # Read output directories
        report_output_dir = config.get('SETTINGS', 'report_output_dir', fallback="/home/imallikarjun/scripts/reports/")
        log_output_dir = config.get('SETTINGS', 'log_output_dir', fallback="/home/imallikarjun/scripts/logs/")

        # Ensure log directory exists *before* configuring logging
        os.makedirs(log_output_dir, exist_ok=True)
        log_filename = os.path.join(log_output_dir, f"{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}_avi_script.log")
        
        # Configure logging
        configure_logging(args.debug, log_filename)
        log(f"Logging configured. Level: {'DEBUG' if args.debug else 'INFO'}", "info")
        log(f"Using metrics: {metrics}", "info")

        # 3. Read CONTROLLERS and their credential directives
        controller_credentials = {}
        if 'CONTROLLERS' in config:
            for controller_name in config._sections['CONTROLLERS'].keys():
                cred_str = config.get('CONTROLLERS', controller_name)
                controller_name_stripped = controller_name.strip()

                if cred_str:
                    parts = cred_str.split(',')
                    if len(parts) == 2:
                        controller_credentials[controller_name_stripped] = (parts[0].strip(), parts[1].strip())
                    else:
                        log(f"Warning: Malformed credentials for '{controller_name_stripped}' in config.ini ('{cred_str}'). Using default credentials for this controller.", "warning")
                        controller_credentials[controller_name_stripped] = (default_avi_user, default_avi_pass)
                else:
                    controller_credentials[controller_name_stripped] = (default_avi_user, default_avi_pass)

        log(f"Loaded {len(controller_credentials)} controllers and their credential directives from config.ini.", "debug")

    except configparser.NoSectionError as e:
        print(f"Error: Missing section in config.ini: {e}. Please ensure [DEFAULT], [CONTROLLERS], and [SETTINGS] sections exist.")
        return
    except Exception as e:
        print(f"Error reading config.ini: {e}. Cannot proceed without proper configuration.")
        return

    if args.controllers:
        controllers_to_process = [c.strip() for c in args.controllers.split(',')]
        valid_controllers = [c for c in controllers_to_process if c in controller_credentials]
        if not valid_controllers:
            log("No valid controllers found after checking config.ini. Exiting.", "error")
            return
        log(f"Processing specified controllers: {', '.join(valid_controllers)}", "info")
    else:
        controllers_to_process = list(controller_credentials.keys())
        if not controllers_to_process:
            log("No controllers found in config.ini or specified via command line. Exiting.", "error")
            return
        log(f"Processing controllers from config.ini: {', '.join(controllers_to_process)}", "info")

    # Ensure report output directory exists
    try:
        os.makedirs(report_output_dir, exist_ok=True)
    except OSError as e:
        log(f"Error creating report output directory '{report_output_dir}': {e}. Please check permissions.", "error")
        log("Exiting script.", "error")
        return

    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    csv_file = os.path.join(report_output_dir, f"avi-VSInventory_{timestamp}.csv")

    with open(csv_file, 'w') as f:
        f.write("Controller,VS Name,VS UUID,VS VIP,Type,VS Enabled,Traffic Enabled,SSL Enabled,State,Reason,PORT,"
                "Primary SE UUID,Primary SE Name,Primary SE Mgmt IP,"
                "Secondary SE UUID,Secondary SE Name,Secondary SE Mgmt IP,"
                f"{','.join(metrics.replace('.', '_').split(','))}\n")

    log(f"CSV report will be saved to: {csv_file}", "info")

    if args.parallel:
        log(f"Parallel processing enabled with {args.processes} workers.", "info")
        with ThreadPoolExecutor(max_workers=args.processes) as executor:
            futures = [executor.submit(process_controller, c, csv_file, default_avi_user, default_avi_pass, controller_credentials) for c in controllers_to_process]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as exc:
                    log(f"An error occurred: {exc}", "error")
    else:
        log("Parallel processing is disabled.", "info")
        for c in controllers_to_process:
            process_controller(c, csv_file, default_avi_user, default_avi_pass, controller_credentials)
    
    log(f"Script finished. Report saved to: {csv_file}", "info")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AVI VS Report with SE Info and Performance Metrics")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging for more detailed output.")
    parser.add_argument('--controllers', type=str, help="Comma-separated list of AVI controllers.")
    parser.add_argument('--metrics', type=str, help="Comma-separated list of metrics to fetch.")
    parser.add_argument('--output-dir', type=str, help="Directory to save the CSV report.")
    parser.add_argument('--parallel', action='store_true', help="Enable parallel processing.")
    parser.add_argument('--processes', type=int, default=10, help="Number of processes to use.")
    
    args = parser.parse_args()
    main(args)
