# sovereign-network-defense

**Open-source cybersecurity detection and defense system for individuals operating on untrusted networks.**

Monitors inbound threats, port scans, unauthorized file access, and suspicious processes with real-time alerts, evidence logging, and automatic blocking capabilities.

## Why This Exists

Most network security tools are designed for enterprises with IT departments, come with recurring subscription costs, or require trusting closed-source vendors with your security data.

**sovereign-network-defense** is built on different principles:
- **No subscriptions** - Own it completely
- **No corporate backdoors** - Full source transparency
- **No cloud dependencies** - Runs entirely on your hardware
- **Evidence-first** - Document what's happening to your network
- **Defense through awareness** - Know what's targeting you

Perfect for:
- Small business owners on public WiFi
- Digital nomads working from cafes and coworking spaces
- Consultants handling sensitive client data
- Anyone who needs to know what's happening on their network connection

## What It Does

### Real-Time Monitoring
- Detects port scanning attempts
- Identifies unauthorized connection attempts  
- Tracks file access patterns
- Monitors process behavior for anomalies

### Evidence Collection
- Timestamped logs of all security events
- Source IP identification and tracking
- Attack pattern documentation
- Exportable reports for legal/compliance purposes

### Automated Response
- Configurable blocking rules
- Alert notifications (email, SMS, desktop)
- Quarantine suspicious activity
- Network isolation options

## Philosophy

This tool operates on a simple premise: **You can't defend what you can't see.**

Traditional security operates reactively - after you've been compromised. This approach inverts that model:

1. **Document everything** - Create an evidence trail
2. **Understand patterns** - Learn what "normal" looks like for your network
3. **Respond intelligently** - Make informed decisions, not emotional reactions
4. **Maintain sovereignty** - Your data, your hardware, your control

We don't believe in security through obscurity. We believe in security through transparency and ownership.

## Installation

### Prerequisites
- Linux-based system (Ubuntu 22.04+ recommended)
- Python 3.10 or higher
- Root/sudo access for network monitoring

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/sovereign-network-defense.git
cd sovereign-network-defense

# Run the installation script
sudo ./install.sh

# Start monitoring
sudo systemctl start sovereign-defense
```

Detailed installation instructions coming soon.

## Configuration

Configuration files are stored in `/etc/sovereign-defense/`:

- `config.yaml` - Main configuration
- `rules.yaml` - Detection and blocking rules
- `alerts.yaml` - Notification settings

Example configuration:
```yaml
monitoring:
  network_interfaces:
    - eth0
    - wlan0
  log_level: INFO
  
alerts:
  email: your@email.com
  desktop_notifications: true
  
blocking:
  auto_block_port_scans: true
  block_threshold: 3
```

## Usage

### Starting the Service
```bash
sudo systemctl start sovereign-defense
```

### Viewing Real-Time Logs
```bash
sudo journalctl -u sovereign-defense -f
```

### Checking Current Threats
```bash
sovereign-defense status
```

### Exporting Evidence Reports
```bash
sovereign-defense export --format pdf --date-range "2024-01-01 to 2024-01-31"
```

## Project Status

**Current Phase:** Initial Development

This project is in active development. Core monitoring functionality is being built first, followed by alert systems and automated response capabilities.

### Roadmap

- [ ] Core network monitoring engine
- [ ] Port scan detection
- [ ] Process monitoring
- [ ] File access tracking
- [ ] Alert notification system
- [ ] Web-based dashboard
- [ ] Mobile app for alerts
- [ ] Machine learning threat detection
- [ ] Integration with firewall systems

## Contributing

Contributions are welcome! This project thrives on community involvement.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Security

If you discover a security vulnerability, please email security@safepassagestrategies.com. Do not open a public issue.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

### Why GPL?

We chose GPL specifically to ensure:
- The source code remains open and auditable
- Modifications must also be open-sourced
- No corporation can take this code proprietary
- Digital sovereignty remains accessible to everyone

## Why "Sovereign"?

Because true security isn't about trusting someone else to protect you. It's about having the tools and knowledge to protect yourself.

Digital sovereignty means:
- Owning your infrastructure
- Understanding your threat landscape
- Making informed decisions based on evidence
- Not depending on corporate or government entities for your security

**For the deeper philosophy behind this project**, see [MANIFESTO.md](MANIFESTO.md)

## Support

- **Documentation:** [Wiki](https://github.com/yourusername/sovereign-network-defense/wiki)
- **Issues:** [GitHub Issues](https://github.com/yourusername/sovereign-network-defense/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/sovereign-network-defense/discussions)

## Acknowledgments

Built for individuals and small businesses who refuse to accept surveillance as inevitable.

Inspired by the principle that awareness is the first line of defense.

---

**You're not a user anymore. You're not a consumer. You're not a data point.**

**You're the monitor now.**

---

---

## A Note on "Legality"

This software is provided for defensive monitoring of your own network infrastructure.

We will not insult your intelligence by telling you to "use responsibly and in accordance with applicable laws" when:

- The judicial system doesn't follow its own rules
- Surveillance entities operate outside legal constraints while prosecuting individuals for far less
- "Legal" simply means "what those in power permit today"
- The entire framework of "computer crimes" laws was written to criminalize awareness

**What this tool actually does:**
- Monitors YOUR network
- Documents what's happening TO you
- Creates evidence of intrusions AGAINST your infrastructure
- Operates defensively, not offensively

**The real legal framework:**
You have the right to monitor your own systems. You have the right to document attacks against your infrastructure. You have the right to keep logs of who's accessing your network.

If monitoring your own network and documenting intrusions against it is "illegal" in your jurisdiction, then the law itself is the criminal enterprise.

**This tool exists so that when they come for you**, you have logs proving:
- You weren't the aggressor
- You were defending yourself
- They were the ones probing, scanning, intruding
- You simply documented their actions

Evidence defeats their narrative.

**You're not "using this responsibly in accordance with applicable laws."**

**You're opting out of a system that was never legitimate to begin with and documenting why.**

---
