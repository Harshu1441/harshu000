import os
import time
import json
import requests
import subprocess
import platform
import psutil
from datetime import datetime
import re
import socket
import uuid
import hashlib

previous_bytes_sent = 0
previous_bytes_recv = 0

# Function to get MAC address
def get_machine_id():
    mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    return hashlib.sha256(mac.encode()).hexdigest()  # Hash the MAC for security

# Function to resolve domain to its IP address
def resolve_domain(domain):
    try:
        nslookup_output = subprocess.check_output(["nslookup", domain]).decode()
        resolved_ip = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', nslookup_output)
        if resolved_ip:
            return resolved_ip.group(1)
    except subprocess.CalledProcessError as e:
        print(f"Error resolving domain '{domain}': {e}")
    return None

# Function to find the full path of an application by process name
def find_application_by_process(app_name):
    for proc in psutil.process_iter(['name', 'exe']):
        if proc.info['name'] and proc.info['name'].lower() == app_name.lower():
            return proc.info['exe']
    return None

# Function to apply firewall rules
def apply_firewall_rules(rules, agent_ip):
    for rule in rules:
        if agent_ip not in rule.get('agent_ips', []):
            continue

        app_name = rule.get('app_name')
        ip_address = rule.get('ip_address')
        domain = rule.get('domain')
        action = rule['action']

        if app_name:
            app_path = find_application_by_process(app_name)
            if not app_path:
                print(f"Application '{app_name}' not found.")
                continue

            if platform.system() == 'Windows':
                if action == 'Block':
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    f"name={app_name}", "dir=out", "action=block",
                                    f"program={app_path}", "enable=yes"])
                elif action == 'Allow':
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                    f"name={app_name}"])
            elif platform.system() == 'Linux':
                if action == 'Block':
                    subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", 
                                    "--dport", "80", "-m", "owner", "--uid-owner", app_path, "-j", "DROP"])
                elif action == 'Allow':
                    subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", 
                                    "--dport", "80", "-m", "owner", "--uid-owner", app_path, "-j", "DROP"])

        if ip_address:
            if platform.system() == 'Windows':
                if action == 'Block':
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    f"name=Block IP {ip_address}", "dir=out", "action=block",
                                    f"remoteip={ip_address}", "enable=yes"])
                elif action == 'Allow':
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                    f"name=Block IP {ip_address}"])
            elif platform.system() == 'Linux':
                if action == 'Block':
                    subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"])
                elif action == 'Allow':
                    subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"])

        if domain:
            resolved_ip = resolve_domain(domain)
            if resolved_ip:
                if platform.system() == 'Windows':
                    if action == 'Block':
                        block_domain_windows(domain)
                    elif action == 'Allow':
                        unblock_domain_windows(domain)
                elif platform.system() == 'Linux':
                    if action == 'Block':
                        subprocess.run(["iptables", "-A", "OUTPUT", "-d", resolved_ip, "-j", "DROP"])
                    elif action == 'Allow':
                        subprocess.run(["iptables", "-D", "OUTPUT", "-d", resolved_ip, "-j", "DROP"])

# Function to fetch firewall rules
def fetch_firewall_rules(server_url, machine_id):
    try:
        headers = {'Machine-ID': machine_id}
        response = requests.get(server_url + '/api/rules', headers=headers)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching rules: {e}")
    return []

# Function to register the agent
def register_agent(server_url, agent_name, agent_ip):
    machine_id = get_machine_id()
    try:
        response = requests.post(server_url + '/api/register', json={
            'name': agent_name,
            'ip': agent_ip,
            'machine_id': machine_id
        })
        if response.status_code == 201:
            print(f"Registered agent '{agent_name}' successfully.")
        else:
            print(f"Failed to register agent: {response.status_code}")
    except Exception as e:
        print(f"Error registering agent: {e}")

# Main function
def main():
    server_url = 'http://13.201.54.125:5500'
    agent_name = platform.node()
    agent_ip = requests.get('https://api.ipify.org').text  # Get public IP
    machine_id = get_machine_id()

    # Register the agent
    register_agent(server_url, agent_name, agent_ip)

    while True:
        # Fetch and apply rules
        rules = fetch_firewall_rules(server_url, machine_id)
        if rules:
            apply_firewall_rules(rules, agent_ip)

        time.sleep(10)

if __name__ == "__main__":
    main()
