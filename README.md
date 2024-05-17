This primarily describes the Fortigate script, but others follow suite.

# Configuration Scripts

This Python script helps automate the configuration of Fortigate devices. It includes initial cleanup commands to remove default configurations and applies new configurations based on user input.

## Features

- Initial cleanup of default configurations
- Configuration of interfaces
- VLAN configuration
- Port speed configuration
- Enabling/disabling ports
- Creation of a virtual interface for management (MGMT)
- Firewall rules configuration

## Prerequisites

- Python 3.x
- `requests` library

You can install the `requests` library using pip: "sudo bash pip install requests"

1.	Clone the repository or download the Fortigate.py script.
2.	Open Command Prompt:
	•	Press Win + R, type cmd, and press Enter.
	•	Alternatively, search for “Command Prompt” in the Start menu and open it.
3.	Navigate to the directory where Fortigate.py is located: then use cd "path\to\your\script"
4.	Run the script: "python Fortigate.py"
5.	Follow the prompts: The script will prompt you for various configuration details. Answer the questions as they appear.

Configuration Details

	•	Fortigate Device IP: The IP address of the Fortigate device used to connect to it.
	•	Username and Password: Credentials to access the Fortigate device.
	•	Interface Configuration: Details for configuring a specific interface (e.g., port1).
	•	VLAN Configuration: Optional VLAN configurations including VLAN ID, name, IP address, and subnet mask.
	•	Port Speeds: Optional configuration for setting port speeds (e.g., 1000full).
	•	Port Status: Optional configuration to enable or disable ports.
	•	Firewall Rules: Optional configuration for firewall rules including rule name, source interface, destination interface, source address, destination address, action, schedule, and service.


EXAMPLE
Enter the Fortigate device IP (the IP used to connect to the device): 192.168.1.1
Enter the username: admin
Enter the password: password
Enter the interface name (e.g., port1): port1
Enter the IP address for the interface: 192.168.2.1
Enter the subnet mask for the interface: 255.255.255.0
Enter the interface description: LAN Interface
Do you want to add VLANs? (yes/no): yes
Enter VLAN ID: 100
Enter VLAN name: MGMT
Enter VLAN IP address: 10.0.0.1
Enter VLAN subnet mask: 255.255.255.0
Do you want to add another VLAN? (yes/no): no
Do you want to configure port speeds? (yes/no): yes
Enter the interface name for speed configuration (e.g., port1): port1
Enter the port speed (e.g., 1000full): 1000full
Do you want to configure another port speed? (yes/no): no
Do you want to enable/disable ports? (yes/no): yes
Enter the interface name to enable/disable (e.g., port1): port2
Enter the status (enable/disable): disable
Do you want to configure another port status? (yes/no): no
Do you want to add firewall rules? (yes/no): yes
Enter rule name: Allow_HTTP
Enter source interface: port1
Enter destination interface: port2
Enter source address: 192.168.2.0/24
Enter destination address: 0.0.0.0/0
Enter action (accept/deny): accept
Enter schedule (e.g., always): always
Enter service (e.g., ALL): HTTP
Do you want to add another rule? (yes/no): no
