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


previous_bytes_sent = 0
previous_bytes_recv = 0



def get_encrypted_mac():
    mac = hex(uuid.getnode())[2:].upper()
    mac_address = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))
    encrypted_mac = hashlib.sha256(mac_address.encode()).hexdigest()
    return encrypted_mac

# Function to find the full path of an application based on its name
def find_application_path(app_name):
    if platform.system() == 'Windows':
        possible_dirs = [
            os.environ['ProgramFiles'],
            os.environ['ProgramFiles(x86)'],
            os.environ['SystemRoot'] + r'\System32',
            os.environ['SystemRoot'] + r'\SysWOW64'
        ]
        for directory in possible_dirs:
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.lower().startswith(app_name.lower()) and file.endswith('.exe'):
                        return os.path.join(root, file)

    elif platform.system() == 'Linux':
        possible_dirs = ['/usr/bin', '/usr/local/bin']
        for directory in possible_dirs:
            for file in os.listdir(directory):
                if file.lower() == app_name.lower():
                    return os.path.join(directory, file)

    return None















def log_application_activity():
    """
    Logs the activity of all running applications (processes).
    """
    print("Logging application activity...")
    logs = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_info']):
        try:
            process_info = proc.info
            logs.append({
                "time": datetime.now().isoformat(),
                "name": process_info['name'],
                "pid": process_info['pid'],
                "user": process_info.get('username', 'N/A'),
                "status": process_info['status'],
                "cpu": process_info['cpu_percent'],
                "memory": process_info['memory_info'].rss / 1024 ** 2  # Memory in MB
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return logs


def log_service_activity():
    """
    Logs the activity of all system services.
    """
    print("Logging service activity...")
    logs = []
    try:
        if platform.system() == "Windows":
            for service in psutil.win_service_iter():
                try:
                    logs.append({
                        "time": datetime.now().isoformat(),
                        "name": service.name(),
                        "display_name": service.display_name(),
                        "status": service.status()
                    })
                except Exception as e:
                    print(f"Error logging service: {e}")
        elif platform.system() == "Linux":
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.splitlines()[1:]  # Skip the header
                for line in lines:
                    columns = line.split(None, 4)  # Split into up to 5 parts
                    if len(columns) >= 2:
                        logs.append({
                            "time": datetime.now().isoformat(),
                            "name": columns[0],
                            "status": "running"
                        })
    except Exception as e:
        print(f"Error logging service activity: {e}")
    return logs



















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

# Function to block domains by modifying the hosts file (Windows-specific)
def block_domain_windows(domain):
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, 'r+') as file:
            hosts_content = file.read()
            if domain not in hosts_content:
                file.write(f"\n127.0.0.1 {domain}\n")
                print(f"Domain '{domain}' blocked.")
            else:
                print(f"Domain '{domain}' already blocked.")
    except PermissionError:
        print("Permission denied: run as administrator.")
    except Exception as e:
        print(f"Error blocking domain '{domain}': {e}")

# Function to unblock domain (Windows-specific)
def unblock_domain_windows(domain):
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, 'r') as file:
            lines = file.readlines()

        with open(hosts_path, 'w') as file:
            for line in lines:
                if domain not in line:
                    file.write(line)

        print(f"Domain '{domain}' unblocked.")
    except PermissionError:
        print("Permission denied: run as administrator.")
    except Exception as e:
        print(f"Error unblocking domain '{domain}': {e}")

# Function to apply firewall rules from the server
def apply_firewall_rules(rules):
    for rule in rules:
        app_name = rule.get('app_name')
        ip_address = rule.get('ip_address')
        domain = rule.get('domain')
        action = rule['action']

        if app_name:
            app_path = find_application_path(app_name)
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














# Log network activity for apps or default logs
def log_network_activity(app_name=None):
    connections = psutil.net_connections(kind='inet')
    logs = []
    for conn in connections:
        if conn.laddr and conn.raddr:
            log_entry = {
                "time": str(datetime.now()),
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                "status": conn.status
            }
            if app_name:
                try:
                    process = psutil.Process(conn.pid)
                    if process.name().lower() == app_name.lower():
                        logs.append(log_entry)
                except psutil.NoSuchProcess:
                    continue
            else:
                logs.append(log_entry)
    return logs

# Send network logs to the server
def send_logs_to_server(server_url, logs):
    try:
        response = requests.post(server_url + '/api/logs', json=logs)
        if response.status_code == 200:
            print("Logs successfully sent.")
        else:
            print(f"Failed to send logs: {response.status_code}")
    except Exception as e:
        print(f"Error sending logs: {e}")




# Register agent with the server
import hashlib
import uuid


# Function to get MAC address and encrypt it



# Update the register_agent function to send the encrypted MAC address
def register_agent(server_url, agent_name, agent_ip):
    encrypted_mac = get_encrypted_mac()  # Get encrypted MAC address
    try:
        response = requests.post(
            f"{server_url}/api/register",
            json={'name': agent_name, 'ip': agent_ip, 'mac_address': encrypted_mac}
        )
        if response.status_code == 201:
            print(f"Registered agent '{agent_name}' with IP '{agent_ip}' successfully.")
        elif response.status_code == 200:
            print(f"Agent already registered.")
        else:
            print(f"Failed to register agent: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error registering agent: {e}")



# Function to get a list of open ports
# Function to get a list of open ports with their service names
def get_open_ports():
    connections = psutil.net_connections(kind='inet')
    open_ports = []
    for conn in connections:
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            try:
                # Try to get the service name for the port
                service_name = socket.getservbyport(port, 'tcp') if port else 'unknown'
            except OSError:
                # Fallback to 'unknown' if the service name is not found
                service_name = 'unknown'
            
            open_ports.append({
                'port': port,
                'service': service_name
            })
    return open_ports


# Function to send open ports count to the server
def send_open_ports_list(server_url, agent_ip):
    open_ports = get_open_ports()  # Get the list of open ports with service names
    try:
        response = requests.post(server_url + '/api/open_ports', json={'ip': agent_ip, 'open_ports': open_ports})
        if response.status_code == 200:
            print(f"Sent open ports list with services: {open_ports} for agent '{agent_ip}'.")
        else:
            print(f"Failed to send open ports list: {response.status_code}")
    except Exception as e:
        print(f"Error sending open ports list: {e}")


'''
def main():
    server_url = 'http://20.51.249.42:80'  # Replace with your Flask server IP
    agent_name = platform.node()  # Use the PC name as the agent name
    agent_ip = requests.get('https://api.ipify.org').text  # Get the public IP address

    # Register the agent with the server
    register_agent(server_url, agent_name, agent_ip)

    while True:
        # Fetch and apply firewall rules
        rules = fetch_firewall_rules(server_url)
        if rules:
            apply_firewall_rules(rules)

        # Log and send network activity
        logs = log_network_activity()
        send_logs_to_server(server_url, logs)

        time.sleep(10)

if __name__ == '__main__':
    main()''' #1

'''def main():
    server_url = 'http://20.51.249.42:80'
    #server_url = 'http://localhost:80' # Replace with your Flask server IP
    agent_name = platform.node()  # Use the PC name as the agent name
    agent_ip = requests.get('https://api.ipify.org').text  # Get the public IP address

    # Register the agent with the server
    register_agent(server_url, agent_name, agent_ip)

    while True:
        # Send open ports count to the server periodically
        rules = fetch_firewall_rules(server_url)
        if rules:
            apply_firewall_rules(rules)
        
        logs = log_network_activity()
        send_logs_to_server(server_url, logs)
        send_open_ports_list(server_url, agent_ip)
        time.sleep(10)

if __name__ == '__main__':
    main()
'''#2
# Function to get current bandwidth usage
def get_bandwidth_usage():
    global previous_bytes_sent, previous_bytes_recv

    # Get network IO statistics
    net_io = psutil.net_io_counters()
    
    # Calculate current bytes sent and received
    current_bytes_sent = net_io.bytes_sent
    current_bytes_recv = net_io.bytes_recv

    # Calculate the delta in sent and received bytes
    delta_bytes_sent = current_bytes_sent - previous_bytes_sent
    delta_bytes_recv = current_bytes_recv - previous_bytes_recv

    # Update previous bytes
    previous_bytes_sent = current_bytes_sent
    previous_bytes_recv = current_bytes_recv

    # Convert bytes to MB
    current_usage = (delta_bytes_sent + delta_bytes_recv) / (1024 * 1024)  # MB

    return current_usage

# Function to check bandwidth usage and send alert
def check_bandwidth_and_send_alert(server_url, threshold=5):
    current_usage = get_bandwidth_usage()

    if current_usage > threshold:
        alert_data = {
            "agent_ip": requests.get('https://api.ipify.org').text,  # Get the public IP address
            "threshold": threshold,
            "current_usage": current_usage,
            "alert_type": "Bandwidth Exceeded"
        }

        # Send the alert to the server
        try:
            response = requests.post(server_url + '/api/alerts', json=alert_data)
            if response.status_code == 200:
                print(f"Alert sent: {alert_data}")
            else:
                print(f"Error sending alert: {response.status_code}")
        except Exception as e:
            print(f"Error sending alert: {e}")

import uuid

def get_mac_address():
    mac = hex(uuid.getnode())[2:].upper()
    return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))



import subprocess

def get_public_ip():
    try:
        result = subprocess.check_output(['curl', '-s', 'https://ifconfig.me']).decode('utf-8').strip()
        return result
    except Exception as e:
        print(f"Error fetching public IP: {e}")
        return None

agent_ip = get_public_ip()


def post_data_to_server(endpoint, logs, agent_ip):
    """
    Sends data to the specified server endpoint with agent information.
    :param endpoint: The server endpoint to which data should be sent.
    :param logs: The logs data to send (list of dictionaries).
    :param agent_ip: The agent's IP address.
    """
    try:
        # Add agent IP to each log
        for log in logs:
            log['agent_ip'] = agent_ip

        # Send data to the server
        response = requests.post(endpoint, json=logs)
        if response.status_code == 200:
            print(f"Data sent successfully to {endpoint}.")
        else:
            print(f"Failed to send data: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending data to {endpoint}: {e}")







def encrypt_mac_address(mac_address):
    return hashlib.sha256(mac_address.encode()).hexdigest()



def fetch_firewall_rules(server_url, encrypted_mac):
    headers = {"Encrypted-MAC": encrypted_mac}
    try:
        response = requests.get(f"{server_url}/api/rules", headers=headers)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching rules: {e}")
    return []


import subprocess
import requests


# Maintain a global set to store previously sent URLs
sent_urls = set()


def fetch_dns_cache_windows():
    """
    Fetch DNS cache on Windows.
    :return: List of DNS cache entries with details.
    """
    dns_cache = []
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            shell=True
        )

        if result.returncode == 0:
            output = result.stdout
            lines = output.splitlines()

            record = {}
            for line in lines:
                line = line.strip()

                if line.startswith("Record Name"):
                    if record:
                        dns_cache.append(record)
                        record = {}
                    record["URL"] = line.split(":")[1].strip()

                elif line.startswith("A (Host) Record"):
                    record["IPv4 Address"] = line.split(":")[1].strip()

                elif line.startswith("AAAA Record"):
                    record["IPv6 Address"] = line.split(":")[1].strip()

            if record:
                dns_cache.append(record)

        return dns_cache

    except Exception as e:
        print(f"Error fetching DNS cache: {e}")
        return []


def filter_new_entries(dns_cache):
    """
    Filter DNS cache to only include new entries.
    :param dns_cache: List of DNS cache entries.
    :return: Filtered list of new DNS entries.
    """
    global sent_urls
    new_entries = []

    for entry in dns_cache:
        url = entry.get("URL")
        if url and url not in sent_urls:
            new_entries.append(entry)
            sent_urls.add(url)

    return new_entries


def log_service_activity():
    """
    Logs the activity of all system services.
    """
    print("Logging service activity...")
    logs = []
    try:
        if platform.system() == "Windows":
            for service in psutil.win_service_iter():
                try:
                    logs.append({
                        "time": datetime.now().isoformat(),
                        "name": service.name(),
                        "display_name": service.display_name(),
                        "status": service.status()
                    })
                except Exception as e:
                    print(f"Error logging service: {e}")
        elif platform.system() == "Linux":
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.splitlines()[1:]  # Skip the header
                for line in lines:
                    columns = line.split(None, 4)  # Split into up to 5 parts
                    if len(columns) >= 2:
                        logs.append({
                            "time": datetime.now().isoformat(),
                            "name": columns[0],
                            "status": "running"
                        })
    except Exception as e:
        print(f"Error logging service activity: {e}")
    return logs



def send_dns_history_to_server(server_url, dns_cache):
    """
    Send DNS history to the server.
    """
    try:
        new_entries = filter_new_entries(dns_cache)
        if not new_entries:
            print("No new DNS entries to send.")
            return

        response = requests.post(f"{server_url}/api/dns_history", json=new_entries)
        if response.status_code == 200:
            print("DNS history sent successfully.")
        else:
            print(f"Failed to send DNS history: {response.text}")
    except Exception as e:
        print(f"Error sending DNS history: {e}")






# Main function to run the agent
def main():
    server_url = 'http://13.201.54.125:5500' 
    encrypted_mac = get_encrypted_mac()
    #server_url = 'http://localhost:80'# Replace with your server URL
    agent_name = platform.node()  # Use the PC name as the agent name
      # Get the public IP address

    # Register the agent with the server
    register_agent(server_url, agent_name, agent_ip)

    while True:
        # Check bandwidth usage and send alert if necessary

        app_logs = log_application_activity()
        service_logs = log_service_activity()


        post_data_to_server(f"{server_url}/api/application_logs", app_logs, agent_ip)
        post_data_to_server(f"{server_url}/api/service_logs", service_logs, agent_ip)


        # Log and send service activity

        check_bandwidth_and_send_alert(server_url)

        # Fetch and apply firewall rules
        rules = fetch_firewall_rules(server_url, encrypted_mac)
        if rules:
            apply_firewall_rules(rules)

        dns_cache = fetch_dns_cache_windows()
        if dns_cache:
            send_dns_history_to_server(server_url, dns_cache)

        logs = log_network_activity()
        send_logs_to_server(server_url, logs)
        send_open_ports_list(server_url, agent_ip)
        time.sleep(10)  # Adjust the sleep time as needed

if __name__ == "__main__":
    main()
