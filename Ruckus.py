import requests

def get_user_input():
    config = {}

    # Ask questions and store answers
    config['device_ip'] = input("Enter the Ruckus device IP: ")
    config['username'] = input("Enter the username: ")
    config['password'] = input("Enter the password: ")

    # Ask for WLAN configuration details
    config['wlan_name'] = input("Enter the WLAN name: ")
    config['ssid'] = input("Enter the SSID: ")
    config['encryption'] = input("Enter the encryption type (open/wep/wpa/wpa2): ")
    if config['encryption'] != 'open':
        config['passphrase'] = input("Enter the passphrase: ")

    # VLAN configuration
    config['vlans'] = []
    add_vlans = input("Do you want to add VLANs? (yes/no): ").lower()
    if add_vlans == 'yes':
        while True:
            vlan = {}
            vlan['id'] = input("Enter VLAN ID: ")
            vlan['name'] = input("Enter VLAN name: ")
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
            port_speed['port'] = input("Enter the port ID for speed configuration: ")
            port_speed['speed'] = input("Enter the port speed (e.g., auto, 1000full, 100full): ")
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
            port_status['port'] = input("Enter the port ID to enable/disable: ")
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
            rule['src_ip'] = input("Enter source IP: ")
            rule['src_port'] = input("Enter source port (leave blank for any): ")
            rule['dest_ip'] = input("Enter destination IP: ")
            rule['dest_port'] = input("Enter destination port (leave blank for any): ")
            rule['protocol'] = input("Enter protocol (tcp/udp/any): ")
            rule['action'] = input("Enter action (allow/deny): ")

            config['firewall_rules'].append(rule)

            more_rules = input("Do you want to add another rule? (yes/no): ").lower()
            if more_rules != 'yes':
                break

    return config

def generate_ruckus_script(config):
    script = f"""
import requests

# Define Ruckus API credentials and base URL
device_ip = '{config['device_ip']}'
username = '{config['username']}'
password = '{config['password']}'
BASE_URL = f"https://{{device_ip}}/v5_0"

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Authenticate and get session token
login_url = f"{{BASE_URL}}/session"
login_payload = {{
    'username': username,
    'password': password
}}
response = requests.post(login_url, json=login_payload, verify=False)
if response.status_code != 200:
    print("Failed to authenticate")
    exit()

session = response.cookies

# Initial cleanup commands
cleanup_commands = [
    "config",
    "no wlan all",
    "no vlan all",
    "no firewall-policy all",
    "exit"
]

for command in cleanup_commands:
    cleanup_url = f"{{BASE_URL}}/cli"
    cleanup_payload = {{
        'cmd': command
    }}
    response = requests.post(cleanup_url, cookies=session, json=cleanup_payload, verify=False)
    print(f"Cleanup command '{command}' response: {{response.status_code}}")

# Configure WLAN
wlan_url = f"{{BASE_URL}}/wlan"
wlan_payload = {{
    'name': '{config['wlan_name']}',
    'ssid': '{config['ssid']}',
    'encryption': '{config['encryption']}'
}}
if config['encryption'] != 'open':
    wlan_payload['passphrase'] = '{config['passphrase']}'
response = requests.post(wlan_url, cookies=session, json=wlan_payload, verify=False)
print(f"WLAN configuration response: {{response.status_code}}")

# Configure VLANs
if {len(config['vlans'])} > 0:
    for vlan in config['vlans']:
        vlan_url = f"{{BASE_URL}}/vlan"
        vlan_payload = {{
            'id': vlan['id'],
            'name': vlan['name']
        }}
        response = requests.post(vlan_url, cookies=session, json=vlan_payload, verify=False)
        print(f"VLAN configuration response for VLAN {{vlan['id']}}: {{response.status_code}}")

# Configure port speeds
if {len(config['port_speeds'])} > 0:
    for port_speed in config['port_speeds']:
        port_url = f"{{BASE_URL}}/ports/{{port_speed['port']}}"
        port_payload = {{
            'speed': '{port_speed['speed']}'
        }}
        response = requests.put(port_url, cookies=session, json=port_payload, verify=False)
        print(f"Port speed configuration response for port {{port_speed['port']}}: {{response.status_code}}")

# Enable/disable ports
if {len(config['port_status'])} > 0:
    for port_status in config['port_status']:
        port_url = f"{{BASE_URL}}/ports/{{port_status['port']}}"
        port_payload = {{
            'enabled': {str(port_status['status'] == 'enable').lower()}
        }}
        response = requests.put(port_url, cookies=session, json=port_payload, verify=False)
        print(f"Port status configuration response for port {{port_status['port']}}: {{response.status_code}}")

# Configure firewall rules if any
if {len(config['firewall_rules'])} > 0:
    for rule in config['firewall_rules']:
        rule_url = f"{{BASE_URL}}/firewall/rules"
        rule_payload = {{
            'name': rule['name'],
            'src_ip': rule['src_ip'],
            'src_port': rule['src_port'],
            'dest_ip': rule['dest_ip'],
            'dest_port': rule['dest_port'],
            'protocol': rule['protocol'],
            'action': rule['action']
        }}
        response = requests.post(rule_url, cookies=session, json=rule_payload, verify=False)
        print(f"Firewall rule configuration response for rule '{{rule['name']}}': {{response.status_code}}")
"""

    return script

def main():
    try:
        config = get_user_input()
        script = generate_ruckus_script(config)
        print("Generated Ruckus Script:")
        print(script)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
