#!/usr/bin/env python3
"""
External Health Monitor for VMware NSX Advanced Load Balancer (Avi)
Uses Paramiko to SSH into backend server and run 'ipcs -qa | grep 1d6c91 | wc -l'

Exit 0 → healthy (output == '1')
Exit 1 → unhealthy (any other output or error)
"""

import os
import sys
import paramiko

# Avi passes server details as environment variables:
server_ip = os.environ.get('IP')      # Backend server IP
server_port = int(os.environ.get('PORT', 22))  # Default SSH port 22

# Hard-coded credentials:
username = "myuser"       # change this
password = "mypassword"   # change this

remote_command = "ipcs -qa | grep 1d6c91 | wc -l"

try:
    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(server_ip, port=server_port, username=username, password=password, timeout=10)

    stdin, stdout, stderr = ssh.exec_command(remote_command, timeout=10)

    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    ssh.close()

    if error:
        sys.exit(1)  # mark server down on error

    if output == "1":
        sys.exit(0)  # healthy
    else:
        sys.exit(1)  # unhealthy

except Exception:
    sys.exit(1)  # any exception → unhealthy
