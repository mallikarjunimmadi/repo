[default]
controller   = m00avientlb
username     = admin
password     = <redacted>
avi_version  = 22.1.7
tenant       = admin

log_dir      = logs
output_dir   = output
limit        = 720

# --------- Virtual Services (existing) ---------
# Defaults (comma- or newline-separated). Leave empty to skip.
metrics_default =
  l4_client.avg_complete_conns,
  l4_client.avg_bandwidth,
  l4_client.avg_connections_dropped,
  l4_client.avg_lossy_connections,
  l4_client.avg_new_established_conns,
  l4_client.max_open_conns,
  l7_client.avg_complete_responses,
  l7_client.avg_connection_time,
  l7_client.avg_resp_1xx,
  l7_client.avg_resp_2xx,
  l7_client.avg_resp_3xx,
  l7_client.avg_resp_4xx,
  l7_client.avg_resp_4xx_avi_errors,
  l7_client.avg_resp_5xx,
  l7_client.avg_resp_5xx_avi_errors,
  l7_client.avg_ssl_connections,
  l7_client.avg_ssl_handshakes_new,
  l7_client.avg_total_requests,
  l7_client.max_ssl_open_sessions,
  l7_client.sum_total_responses

vs_uuids =
  virtualservice-4d7fbd00-92fc-447a-aa30-2847b64de963

# --------- Pools (new) ---------
pool_metrics_default =
  l4_server.avg_complete_conns,
  l4_server.avg_bandwidth,
  l4_server.avg_new_established_conns,
  l7_server.avg_total_requests

pool_uuids =
  pool-12345678-aaaa-bbbb-cccc-1234567890ab

# --------- Service Engines (new) ---------
se_metrics_default =
  se_stats.packets_in,
  se_stats.packets_out,
  se_if.avg_bandwidth

se_uuids =
  serviceengine-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
