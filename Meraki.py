def get_user_input():
    config = {}

    # Ask questions and store answers
    config['organization_id'] = input("Enter the organization ID: ")
    config['network_id'] = input("Enter the network ID: ")
    config['device_serial'] = input("Enter the device serial number: ")

    # Ask for device configuration details
    config['device_name'] = input("Enter the device name: ")
    config['device_tags'] = input("Enter the device tags (comma-separated): ")
    config['static_ip'] = input("Enter the static IP address (leave blank if DHCP): ")

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
API_KEY = 'YOUR_MERAKI_API_KEY'
BASE_URL = 'https://api.meraki.com/api/v1'

headers = {{
    'X-Cisco-Meraki-API-Key': API_KEY,
    'Content-Type': 'application/json'
}}

# Set device details
organization_id = '{config['organization_id']}'
network_id = '{config['network_id']}'
device_serial = '{config['device_serial']}'

# Update device details
device_url = f"{{BASE_URL}}/networks/{{network_id}}/devices/{{device_serial}}"
device_payload = {{
    'name': '{config['device_name']}',
    'tags': '{config['device_tags']}',
    'staticIp': '{config['static_ip']}'
}}
response = requests.put(device_url, headers=headers, json=device_payload)
print(f"Device update response: {{response.status_code}}")

# Update firewall rules if any
if {len(config['firewall_rules'])} > 0:
    firewall_url = f"{{BASE_URL}}/networks/{{network_id}}/appliance/firewall/l3FirewallRules"
    firewall_payload = {{
        'rules': {config['firewall_rules']}
    }}
    response = requests.put(firewall_url, headers=headers, json=firewall_payload)
    print(f"Firewall rules update response: {{response.status_code}}")
"""

    return script

def main():
    config = get_user_input()
    script = generate_meraki_script(config)
    print("Generated Meraki Script:")
    print(script)

if __name__ == "__main__":
    main()