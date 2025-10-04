#!/usr/bin/env python3
import paramiko
import getpass

# Remote host details
hostname = input("Enter remote host/IP: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

# The command you want to run
command = "ipcs -qa | grep 1d6c91 | wc -l"

try:
    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to remote host
    ssh.connect(hostname, username=username, password=password)

    # Execute command
    stdin, stdout, stderr = ssh.exec_command(command)

    # Read outputs
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    if error:
        print("Error:\n", error)
    else:
        print(f"Output from {hostname}:\n{output}")

    ssh.close()

except Exception as e:
    print(f"Connection failed: {e}")
