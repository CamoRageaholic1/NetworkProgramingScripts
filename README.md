# Network Programming Scripts

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Network](https://img.shields.io/badge/Network-Automation-0078D6?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge)

**Automated configuration scripts for network engineers** - Interactive Python tools that guide junior network professionals through device setup via questionnaire-style prompts.

## 🎯 Purpose

These scripts are designed to help junior network engineers learn and automate network device configurations without memorizing complex CLI commands. Each script provides an interactive questionnaire that generates the appropriate configuration commands based on your answers.

**Perfect for:**
- 🎓 Junior Network Engineers learning configuration best practices
- 🏢 Training Labs requiring consistent device setup
- 📚 Educational environments and certification prep
- ⚡ Reducing manual configuration errors and saving time

## 📦 Supported Devices

| Script | Vendor | Description |
|--------|--------|-------------|
| `Fortigate.py` | FortiGate | Firewall configuration including interfaces, VLANs, port speeds, and firewall rules |
| `Meraki.py` | Cisco Meraki | Cloud-managed network device configuration |
| `Ruckus.py` | Ruckus Wireless | Wireless controller and access point setup |

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Network access to target devices
- Valid credentials for device management

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/CamoRageaholic1/NetworkProgramingScripts.git
   cd NetworkProgramingScripts
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Usage

Run any script and follow the interactive prompts:

```bash
# FortiGate Configuration
python Fortigate.py

# Cisco Meraki Configuration
python Meraki.py

# Ruckus Wireless Configuration
python Ruckus.py
```

## 📋 Example Workflow: FortiGate Configuration

The script will guide you through a series of questions:

```
Enter the Fortigate device IP: 192.168.1.1
Enter the username: admin
Enter the password: ********

=== Interface Configuration ===
Enter the interface name (e.g., port1): port1
Enter the IP address: 192.168.2.1
Enter the subnet mask: 255.255.255.0
Enter interface description: LAN Interface

=== VLAN Configuration ===
Do you want to add VLANs? (yes/no): yes
Enter VLAN ID: 100
Enter VLAN name: MGMT
Enter VLAN IP address: 10.0.0.1
Enter VLAN subnet mask: 255.255.255.0

=== Port Configuration ===
Do you want to configure port speeds? (yes/no): yes
Enter interface name: port1
Enter port speed (e.g., 1000full): 1000full

=== Firewall Rules ===
Do you want to add firewall rules? (yes/no): yes
Enter rule name: Allow_HTTP
Enter source interface: port1
Enter destination interface: port2
Enter source address: 192.168.2.0/24
Enter destination address: 0.0.0.0/0
Enter action (accept/deny): accept
Enter service: HTTP
```

## 🔧 Features

### FortiGate Script
- ✅ Initial cleanup of default configurations
- ✅ Interface configuration (IP, subnet, description)
- ✅ VLAN creation and management
- ✅ Port speed configuration
- ✅ Port enable/disable management
- ✅ Virtual management interface (MGMT)
- ✅ Firewall policy creation

### Meraki Script
- ✅ Organization and network setup
- ✅ Device provisioning
- ✅ SSID configuration
- ✅ Firewall rules

### Ruckus Script
- ✅ Wireless controller configuration
- ✅ Access point provisioning
- ✅ WLAN creation
- ✅ Security settings

## ⚠️ Important Notes

### Before Running Scripts

- **Test Environment First**: Always test in a lab environment before production
- **Backup Configurations**: Back up existing device configs before making changes
- **Verify Access**: Ensure you have proper credentials and network access
- **Review Output**: Always review generated configurations before applying

### Security Best Practices

- 🔒 Use strong passwords for device access
- 🔒 Never commit credentials to version control
- 🔒 Implement least-privilege access principles
- 🔒 Enable device logging and monitoring
- 🔒 Review firewall rules carefully before deployment

## 🎓 Educational Use

These scripts serve as both automation tools and learning resources:

**For Students:**
- Understand what commands are being executed
- Learn configuration best practices
- See how different settings interact

**For Instructors:**
- Consistent lab setup across multiple devices
- Reduce setup time for hands-on exercises
- Focus teaching on concepts rather than syntax

## 📁 Project Structure

```
NetworkProgramingScripts/
├── Fortigate.py          # FortiGate firewall configuration
├── Meraki.py             # Cisco Meraki configuration
├── Ruckus.py             # Ruckus wireless configuration
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── LICENSE              # MIT License
└── .gitignore           # Git ignore rules
```

## 🤝 Contributing

Contributions are welcome! Whether you want to add support for new vendors, improve existing scripts, or fix bugs:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-vendor`)
3. Commit your changes (`git commit -m 'Add support for new vendor'`)
4. Push to the branch (`git push origin feature/new-vendor`)
5. Open a Pull Request

**Ideas for contributions:**
- Additional vendor support (Ubiquiti, Aruba, Juniper, etc.)
- Enhanced error handling
- Configuration templates
- Batch device configuration
- Output logging and reporting

## 📝 Roadmap

- [ ] Add Ubiquiti UniFi support
- [ ] Implement configuration backup/restore
- [ ] Add batch processing for multiple devices
- [ ] Create web-based UI
- [ ] Add configuration validation
- [ ] Support for configuration templates
- [ ] Integration with network monitoring tools

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📫 Support

- 🐛 **Bug Reports**: Open an issue on GitHub
- 💡 **Feature Requests**: Open an issue with the "enhancement" label
- 📧 **Contact**: For other inquiries, reach out via GitHub

## 🙏 Acknowledgments

Built by network engineers, for network engineers. Special thanks to the networking community for feedback and contributions.

---

**Made with ❤️ by [CamoZeroDay](https://github.com/CamoRageaholic1)**
