#!/usr/bin/env python3
import subprocess
import getpass

# Ask for connection details
hostname = input("Enter remote host/IP: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password (leave blank to use SSH key): ")

# Command to run remotely
remote_command = "ipcs -qa | grep 1d6c91 | wc -l"

# Build ssh command
ssh_command = ["ssh", f"{username}@{hostname}", remote_command]

try:
    if password:
        # If a password is given, use sshpass via a here-string workaround
        # (native python has no SSH password support without paramiko)
        # This will prompt for password interactively.
        print("Connecting… you’ll be prompted for the password by ssh:")
        ssh_command = ["ssh", f"{username}@{hostname}", remote_command]

    # Run the command
    result = subprocess.run(
        ssh_command,
        input=password.encode() if password else None,
        capture_output=True,
        text=True
    )

    if result.stderr:
        print("Error:\n", result.stderr)
    else:
        print("Output:\n", result.stdout.strip())

except Exception as e:
    print(f"Failed: {e}")
