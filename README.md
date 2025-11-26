# Network Programming Scripts

**Automated configuration scripts for network engineers** - Interactive Python tools that guide junior network professionals through device setup via questionnaire-style prompts.

## 🎯 Purpose

These scripts are designed to help junior network engineers learn and automate network device configurations without memorizing complex CLI commands. Each script provides an interactive questionnaire that generates the appropriate configuration commands based on your answers.

## 📦 Available Scripts

### 1. **Fortigate.py** - FortiGate Firewall Configuration
Automates FortiGate device setup including:
- Initial cleanup of default configurations
- Interface configuration
- VLAN setup
- Port speed configuration
- Port enable/disable
- Virtual management interface creation
- Firewall rules

### 2. **Meraki.py** - Cisco Meraki Configuration
Interactive configuration for Cisco Meraki devices

### 3. **Ruckus.py** - Ruckus Wireless Configuration
Automated setup for Ruckus wireless controllers and access points

## 🚀 Quick Start

### Prerequisites
- Python 3.x
- `requests` library

Install dependencies:
```bash
pip install requests
```

### Running a Script

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/CamoRageaholic1/NetworkProgramingScripts.git
   cd NetworkProgramingScripts
   ```

2. **Run the desired script**
   ```bash
   python Fortigate.py
   # or
   python Meraki.py
   # or
   python Ruckus.py
   ```

3. **Follow the interactive prompts**
   - Answer questions about your network setup
   - The script generates and applies configurations automatically

## 📋 Example: FortiGate Configuration

```
Enter the Fortigate device IP: 192.168.1.1
Enter the username: admin
Enter the password: ********
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
Enter the interface name for speed configuration: port1
Enter the port speed (e.g., 1000full): 1000full
Do you want to configure another port speed? (yes/no): no

Do you want to enable/disable ports? (yes/no): yes
Enter the interface name to enable/disable: port2
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
```

## 🎓 Educational Use

These scripts are perfect for:
- **Junior Network Engineers** - Learn configuration best practices
- **Training Labs** - Consistent device setup for hands-on learning
- **Documentation** - Understand what configurations are being applied
- **Time Savings** - Reduce manual configuration errors

## ⚠️ Important Notes

- **Test Environment**: Always test scripts in a lab environment before production use
- **Backup Configurations**: Always backup existing device configurations before running scripts
- **Credentials**: Never commit credentials to version control - use environment variables or config files
- **Validation**: Review generated configurations before applying to production devices

## 🔒 Security Considerations

- Use strong passwords for device access
- Implement least-privilege access principles
- Secure API keys and credentials
- Review firewall rules carefully before deployment
- Enable logging and monitoring

## 🤝 Contributing

Contributions are welcome! If you have scripts for other network vendors or improvements to existing scripts:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

MIT License - Feel free to use and modify for your networking needs

## 📫 Support

For questions or issues, please open an issue on GitHub or contact the maintainer.

---

**Made by network engineers, for network engineers** 🌐
