def get_user_input():
    config = {}

    # Ask questions and store answers
    config['device_ip'] = input("Enter the Fortigate device IP (the IP used to connect to the device): ")
    config['username'] = input("Enter the username: ")
    config['password'] = input("Enter the password: ")

    # Ask for interface configuration details
    config['interface_name'] = input("Enter the interface name (e.g., port1): ")
    config['ip_address'] = input("Enter the IP address for the interface: ")
    config['subnet_mask'] = input("Enter the subnet mask for the interface: ")
    config['interface_description'] = input("Enter the interface description: ")

    # VLAN configuration
    config['vlans'] = []
    add_vlans = input("Do you want to add VLANs? (yes/no): ").lower()
    if add_vlans == 'yes':
        while True:
            vlan = {}
            vlan['id'] = input("Enter VLAN ID: ")
            vlan['name'] = input("Enter VLAN name: ")
            vlan['ip'] = input("Enter VLAN IP address: ")
            vlan['subnet_mask'] = input("Enter VLAN subnet mask: ")
            config['vlans'].append(vlan)

            more_vlans = input("Do you want to add another VLAN? (yes/no): ").lower()
            if more_vlans != 'yes':
                break

    # Port speed configuration
    config['port_speeds'] = []
    configure_port_speeds = input("Do you want to configure port speeds? (yes/no): ").lower()
    if configure_port_speeds == 'yes':
        while True:
            port_speed = {}
            port_speed['interface'] = input("Enter the interface name for speed configuration (e.g., port1): ")
            port_speed['speed'] = input("Enter the port speed (e.g., 1000full): ")
            config['port_speeds'].append(port_speed)

            more_speeds = input("Do you want to configure another port speed? (yes/no): ").lower()
            if more_speeds != 'yes':
                break

    # Port enable/disable configuration
    config['port_status'] = []
    configure_port_status = input("Do you want to enable/disable ports? (yes/no): ").lower()
    if configure_port_status == 'yes':
        while True:
            port_status = {}
            port_status['interface'] = input("Enter the interface name to enable/disable (e.g., port1): ")
            port_status['status'] = input("Enter the status (enable/disable): ").lower()
            config['port_status'].append(port_status)

            more_status = input("Do you want to configure another port status? (yes/no): ").lower()
            if more_status != 'yes':
                break

    # Optional firewall rules
    add_firewall_rules = input("Do you want to add firewall rules? (yes/no): ").lower()
    config['firewall_rules'] = []
    if add_firewall_rules == 'yes':
        while True:
            rule = {}
            rule['name'] = input("Enter rule name: ")
            rule['srcintf'] = input("Enter source interface: ")
            rule['dstintf'] = input("Enter destination interface: ")
            rule['srcaddr'] = input("Enter source address: ")
            rule['dstaddr'] = input("Enter destination address: ")
            rule['action'] = input("Enter action (accept/deny): ")
            rule['schedule'] = input("Enter schedule (e.g., always): ")
            rule['service'] = input("Enter service (e.g., ALL): ")

            config['firewall_rules'].append(rule)

            more_rules = input("Do you want to add another rule? (yes/no): ").lower()
            if more_rules != 'yes':
                break

    return config

def generate_fortigate_script(config):
    script = f"""
import requests

# Define Fortigate API credentials and base URL
device_ip = '{config['device_ip']}'
username = '{config['username']}'
password = '{config['password']}'
BASE_URL = f"https://{{device_ip}}/api/v2"

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Authenticate and get session token
login_url = f"{{BASE_URL}}/monitor/user/login"
login_payload = {{
    'username': username,
    'secretkey': password
}}
response = requests.post(login_url, json=login_payload, verify=False)
if response.status_code != 200:
    print("Failed to authenticate")
    exit()

session = response.cookies

# Initial cleanup commands
cleanup_commands = [
    "config firewall policy",
    "delete 1",
    "end",
    "config system dhcp server",
    "delete 1",
    "end",
    "config system interface",
    "edit wan1",
    "set mode static",
    "unset ip",
    "next",
    "edit wan2",
    "set mode static",
    "unset ip",
    "next",
    "edit internal",
    "unset ip",
    "end",
    "config firewall address",
    "delete internal",
    "end"
]

for command in cleanup_commands:
    cleanup_url = f"{{BASE_URL}}/cli"
    cleanup_payload = {{
        'cmd': command
    }}
    response = requests.post(cleanup_url, cookies=session, json=cleanup_payload, verify=False)
    print(f"Cleanup command '{command}' response: {{response.status_code}}")

# Configure interface
interface_url = f"{{BASE_URL}}/cmdb/system/interface/{{config['interface_name']}}"
interface_payload = {{
    'json': {{
        'ip': '{config['ip_address']} {config['subnet_mask']}',
        'allowaccess': 'ping https ssh',
        'description': '{config['interface_description']}'
    }}
}}
response = requests.put(interface_url, cookies=session, json=interface_payload, verify=False)
print(f"Interface configuration response: {{response.status_code}}")

# Configure VLANs
if {len(config['vlans'])} > 0:
    for vlan in config['vlans']:
        vlan_url = f"{{BASE_URL}}/cmdb/system/interface"
        vlan_payload = {{
            'json': {{
                'vlanid': vlan['id'],
                'name': vlan['name'],
                'ip': '{vlan['ip']} {vlan['subnet_mask']}',
                'interface': '{config['interface_name']}'
            }}
        }}
        response = requests.post(vlan_url, cookies=session, json=vlan_payload, verify=False)
        print(f"VLAN configuration response for VLAN {{vlan['id']}}: {{response.status_code}}")

# Configure port speeds
if {len(config['port_speeds'])} > 0:
    for port_speed in config['port_speeds']:
        speed_url = f"{{BASE_URL}}/cmdb/system/interface/{{port_speed['interface']}}"
        speed_payload = {{
            'json': {{
                'speed': '{port_speed['speed']}'
            }}
        }}
        response = requests.put(speed_url, cookies=session, json=speed_payload, verify=False)
        print(f"Port speed configuration response for {{port_speed['interface']}}: {{response.status_code}}")

# Enable/disable ports
if {len(config['port_status'])} > 0:
    for port_status in config['port_status']:
        status_url = f"{{BASE_URL}}/cmdb/system/interface/{{port_status['interface']}}"
        status_payload = {{
            'json': {{
                'status': '{port_status['status']}'
            }}
        }}
        response = requests.put(status_url, cookies=session, json=status_payload, verify=False)
        print(f"Port status configuration response for {{port_status['interface']}}: {{response.status_code}}")

# Configure virtual interface for MGMT
mgmt_interface_url = f"{{BASE_URL}}/cmdb/system/interface"
mgmt_interface_payload = {{
    'json': {{
        'name': 'MGMT',
        'type': 'vlan',
        'vlanid': 100,  # Example VLAN ID for MGMT
        'ip': '10.0.0.1 255.255.255.0',  # Example IP and subnet for MGMT
        'interface': 'internal'  # Parent interface
    }}
}}
response = requests.post(mgmt_interface_url, cookies=session, json=mgmt_interface_payload, verify=False)
print(f"MGMT interface configuration response: {{response.status_code}}")

# Configure firewall rules if any
if {len(config['firewall_rules'])} > 0:
    for rule in config['firewall_rules']:
        rule_url = f"{{BASE_URL}}/cmdb/firewall/policy"
        rule_payload = {{
            'json': {{
                'name': rule['name'],
                'srcintf': [{{ 'name': rule['srcintf'] }}],
                'dstintf': [{{ 'name': rule['dstintf'] }}],
                'srcaddr': [{{ 'name': rule['srcaddr'] }}],
                'dstaddr': [{{ 'name': rule['dstaddr'] }}],
                'action': rule['action'],
                'schedule': rule['schedule'],
                'service': [{{ 'name': rule['service'] }}]
            }}
        }}
        response = requests.post(rule_url, cookies=session, json=rule_payload, verify=False