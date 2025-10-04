Conversation opened. 1 unread message.

Skip to content
Using Broadcom Inc. Mail with screen readers

1 of 30,062
AVI External HM
External
Inbox


Mallikarjun Immadi
Attachments
1:30 PM (1 minute ago)
to me



The information in this mail is confidential and is intended solely for addressee. Access to this mail by anyone else is unauthorized. Copying or further distribution beyond the original recipient may be unlawful. Any opinion expressed in this mail is that of sender and does not necessarily reflect that of State Bank group.
---
 One attachment
  •  Scanned by Gmail
from:immadimallikarjun_vmware@sbi.co.in
#!/usr/bin/python3
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
username = "toolsuser"       # change this
password = "toolsuser"   # change this

#remote_command = "ipcs -qa | grep 1d6c91 | wc -l"
#remote_command = "hostname"
remote_command = "ps -ef | grep grafana | grep -v grep | wc -l"

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
        print(f"ext_hm_usr_err_msg: External HM Failed with {error}" )
        sys.exit(1)  # mark server down on error

    if output == "1":
    #if output == "m00tools01":
        print(f"Success: {output}")
        sys.exit(0)  # healthy
    else:
        print(f"ext_hm_usr_err_msg: External HM Failed with: {output}")
        sys.exit(1)  # unhealthy

except Exception as e:
    print("ext_hm_usr_err_msg: External HM Failed with " + str(e))
    sys.exit(1)  # any exception → unhealthy
