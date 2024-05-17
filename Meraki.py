import requests

def get_user_input():
    config = {}

    # Ask questions and store answers
    config['api_key'] = input("Enter the Meraki API key: ")
    config['organization_id'] = input("Enter the organization ID: ")
    config['network_id'] = input("Enter the network ID: ")

    # Ask for device configuration details
    config['device_serial'] = input("Enter the device serial number: ")
    config['device_name'] = input("Enter the device name: ")

    # VLAN configuration
    config['vlans'] = []
    add_vlans = input("Do you want to add VLANs? (yes/no): ").lower()
    if add_vlans == 'yes':
        while True:
            vlan = {}
            vlan['id'] = input("Enter VLAN ID: ")
            vlan['name'] = input("Enter VLAN name: ")
            vlan['subnet'] = input("Enter VLAN subnet: ")
            vlan['appliance_ip'] = input("Enter VLAN appliance IP: ")
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
            port_speed['port_id'] = input("Enter the port ID for speed configuration: ")
            port_speed['speed'] = input("Enter the port speed (e.g., 1000): ")
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
            port_status['port_id'] = input("Enter the port ID to enable/disable: ")
            port_status['enabled'] = input("Enter the status (enable/disable): ").lower() == 'enable'
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
            rule['comment'] = input("Enter rule comment: ")
            rule['policy'] = input("Enter rule policy (allow/deny): ")
            rule['protocol'] = input("Enter rule protocol (tcp/udp/any): ")
            rule['src_port'] = input("Enter source port (leave blank for any): ")
            rule['src_cidr'] = input("Enter source CIDR: ")
            rule['dest_port'] = input("Enter destination port (leave blank for any): ")
            rule['dest_cidr'] = input("Enter destination CIDR: ")

            config['firewall_rules'].append(rule)

            more_rules = input("Do you want to add another rule? (yes/no): ").lower()
            if more_rules != 'yes':
                break

    return config

def generate_meraki_script(config):
    script = f"""
import requests

# Define Meraki API key and base URL
API_KEY = '{config['api_key']}'
BASE_URL = 'https://api.meraki.com/api/v1'

headers = {{
    'X-Cisco-Meraki-API-Key': API_KEY,
    'Content-Type': 'application/json'
}}

# Initial cleanup commands
cleanup_commands = [
    ("DELETE", f"/organizations/{{config['organization_id']}}/networks/{{config['network_id']}}/firewall/l3FirewallRules"),
    ("DELETE", f"/organizations/{{config['organization_id']}}/networks/{{config['network_id']}}/vlans")
]

for method, endpoint in cleanup_commands:
    url = f"{{BASE_URL}}{{endpoint}}"
    response = requests.request(method, url, headers=headers)
    print(f"Cleanup command for endpoint '{{endpoint}}' response: {{response.status_code}}")

# Set device details
device_url = f"{{BASE_URL}}/networks/{{config['network_id']}}/devices/{{config['device_serial']}}"
device_payload = {{
    'name': '{config['device_name']}'
}}
response = requests.put(device_url, headers=headers, json=device_payload)
print(f"Device update response: {{response.status_code}}")

# Configure VLANs
if {len(config['vlans'])} > 0:
    for vlan in config['vlans']:
        vlan_url = f"{{BASE_URL}}/networks/{{config['network_id']}}/vlans"
        vlan_payload = {{
            'id': vlan['id'],
            'name': vlan['name'],
            'subnet': vlan['subnet'],
            'applianceIp': vlan['appliance_ip']
        }}
        response = requests.post(vlan_url, headers=headers, json=vlan_payload)
        print(f"VLAN configuration response for VLAN {{vlan['id']}}: {{response.status_code}}")

# Configure port speeds
if {len(config['port_speeds'])} > 0:
    for port_speed in config['port_speeds']:
        port_url = f"{{BASE_URL}}/networks/{{config['network_id']}}/devices/{{config['device_serial']}}/switchPorts/{{port_speed['port_id']}}"
        port_payload = {{
            'speed': '{port_speed['speed']}'
        }}
        response = requests.put(port_url, headers=headers, json=port_payload)
        print(f"Port speed configuration response for port {{port_speed['port_id']}}: {{response.status_code}}")

# Enable/disable ports
if {len(config['port_status'])} > 0:
    for port_status in config['port_status']:
        port_url = f"{{BASE_URL}}/networks/{{config['network_id']}}/devices/{{config['device_serial']}}/switchPorts/{{port_status['port_id']}}"
        port_payload = {{
            'enabled': {str(port_status['enabled']).lower()}
        }}
        response = requests.put(port_url, headers=headers, json=port_payload)
        print(f"Port status configuration response for port {{port_status['port_id']}}: {{response.status_code}}")

# Configure firewall rules if any
if {len(config['firewall_rules'])} > 0:
    firewall_url = f"{{BASE_URL}}/networks/{{config['network_id']}}/firewall/l3FirewallRules"
    firewall_payload = {{
        'rules': {config['firewall_rules']}
    }}
    response = requests.put(firewall_url, headers=headers, json=firewall_payload)
    print(f"Firewall rules update response: {{response.status_code}}")
"""

    return script

def main():
    try:
        config = get_user_input()
        script = generate_meraki_script(config)
        print("Generated Meraki Script:")
        print(script)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
