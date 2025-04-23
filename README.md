# secure-linux-server

 #Linux OS Deployment and Networking Security
📝 Project: Secure Linux Web Server Setup
📁 Description:
Automate the deployment of an Ubuntu server that includes:

Firewall rules with ufw / iptables

Secured SSH access

Monitoring setup (e.g., using top, htop, netstat, fail2ban)

Network hardening and SELinux/AppArmor config

🔗 Technologies: Ubuntu, Shell scripting, UFW, fail2ban
✅ Outcome: Hardened Linux environment for secure application hosting
---

```markdown
# 🧩 Project: Secure Linux Web Server Setup

## ✅ Objective
Automate the setup of a hardened Ubuntu server suitable for hosting applications, with:

- 🔒 Network/firewall security  
- 🔐 Secure remote access  
- 📊 Real-time monitoring  
- 🛡️ System hardening  

---

## 📁 Project Structure

```bash
secure-linux-server/
├── scripts/
│   ├── setup-firewall.sh
│   ├── secure-ssh.sh
│   ├── install-monitoring.sh
│   ├── harden-system.sh
├── README.md
└── setup.sh
```

###  `file-setup.py`

```python

import os

# Define the directory and file structure
base_dir = "/home/lilia/VIDEOS/secure-linux-server"
scripts_dir = os.path.join(base_dir, "scripts")
files = {
    "README.md": "",
    "setup.sh": """#!/bin/bash

echo "[*] Starting Secure Ubuntu Server Setup..."

bash scripts/setup-firewall.sh
bash scripts/secure-ssh.sh
bash scripts/install-monitoring.sh
bash scripts/harden-system.sh

echo "[✓] Server secured and ready!"
""",
    "scripts/setup-firewall.sh": """#!/bin/bash

echo "[*] Setting up UFW Firewall..."

sudo apt update && sudo apt install -y ufw

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

sudo ufw --force enable
sudo ufw status verbose
""",
    "scripts/secure-ssh.sh": """#!/bin/bash

echo "[*] Securing SSH..."

sudo sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

sudo systemctl restart ssh
sudo systemctl status ssh
""",
    "scripts/install-monitoring.sh": """#!/bin/bash

echo "[*] Installing monitoring tools..."

sudo apt update
sudo apt install -y htop net-tools fail2ban

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

sudo fail2ban-client status
""",
    "scripts/harden-system.sh": """#!/bin/bash

echo "[*] Applying system hardening..."

sudo apt install -y unattended-upgrades apparmor apparmor-utils

sudo dpkg-reconfigure --priority=low unattended-upgrades

sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo aa-status

sudo systemctl disable --now avahi-daemon
sudo systemctl disable --now cups || true

cat <<EOF | sudo tee /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF

sudo sysctl --system
"""
}

# Create directories
os.makedirs(scripts_dir, exist_ok=True)

# Create files with content
for path, content in files.items():
    file_path = os.path.join(base_dir, path)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        f.write(content)

base_dir



```

---

## 🚀 Step-by-Step Setup with CLI and Scripts

### 🧱 Prerequisites

- Ubuntu 20.04+ (e.g., EC2, VirtualBox, or DigitalOcean droplet)
```bash
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \                   # Ubuntu Server 20.04 LTS
  --count 1 \
  --instance-type t2.micro \
  --key-name ec2-devops-key \                          # Make sure this key exists
  --security-group-ids sg-091906568d27d3894 \          # Should allow SSH (port 22)
  --subnet-id subnet-062bafb72ff1b9c71 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Ubuntu-Server}]'
```

- SSH access as a non-root user with `sudo` privileges
```bash
ssh -i /home/lilia/ec2.pem ubuntu@<INSTANCE_PUBLIC_IP>
sudo adduser devopsadmin   #Create a Non-root User with sudo Access
sudo usermod -aG sudo devopsadmin          #Add to sudo group
```

- SSH key-based login configured (Set Up SSH Key-Based Access for the New User) 
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/devopsadmin-key  #On your local machine
ssh ubuntu@<INSTANCE_PUBLIC_IP>   #Copy the public key to your EC2 instance

sudo mkdir -p /home/devopsadmin/.ssh     #Then on the EC2 instance
sudo nano /home/devopsadmin/.ssh/authorized_keys   # Paste your local devopsadmin-key.pub content here

sudo chown -R devopsadmin:devopsadmin /home/devopsadmin/.ssh   #Set correct permissions
sudo chmod 700 /home/devopsadmin/.ssh
sudo chmod 600 /home/devopsadmin/.ssh/authorized_keys
```


---

### 1️⃣ `setup-firewall.sh`: Configure Firewall (UFW)
- Installs and enables UFW (Uncomplicated Firewall)
- Sets default policy to deny all incoming traffic
- Allows essential ports: SSH (22), HTTP (80), HTTPS (443)


```bash
#!/bin/bash

echo "[*] Setting up UFW Firewall..."

sudo apt update && sudo apt install -y ufw

# Default policy
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential ports
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

---

### 2️⃣ `secure-ssh.sh`: SSH Hardening
- Disables root login via SSH
- Disables password-based SSH authentication to enforce key-based login
- Restarts the SSH daemon to apply changes

```bash
#!/bin/bash

echo "[*] Securing SSH..."

# Disable root login & password auth
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh

# Show status
sudo systemctl status ssh
```

💡 **Note:** Ensure you have SSH keys set up before disabling password authentication.

#### Test SSH Access with New User
On your local machine, connect like this:
```bash
ssh -i ~/.ssh/devopsadmin-key devopsadmin@<INSTANCE_PUBLIC_IP>
```
If it works — you’re now logging in securely with SSH keys and a non-root user!


---

### 3️⃣ `install-monitoring.sh`: Monitoring Tools
- Installs real-time system monitoring tools: htop, net-tools
- Installs and starts fail2ban to ban IPs with repeated failed login attempts

```bash
#!/bin/bash

echo "[*] Installing monitoring tools..."

sudo apt update
sudo apt install -y htop net-tools fail2ban

# Enable fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check fail2ban status
sudo fail2ban-client status
```

---

### 4️⃣ `harden-system.sh`: System Hardening + AppArmor
- Installs and configures:
  . unattended-upgrades for automatic security patching
  . AppArmor for mandatory access control
- Disables unused services (e.g., avahi-daemon, cups)
- Applies kernel-level network hardening via /etc/sysctl.d


```bash
#!/bin/bash

echo "[*] Applying system hardening..."

# Enable automatic updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades

# AppArmor
sudo apt install -y apparmor apparmor-utils
sudo aa-status

# Disable unused services
sudo systemctl disable avahi-daemon
sudo systemctl disable cups

# Sysctl Hardening
cat <<EOF | sudo tee /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF

sudo sysctl --system
```

---

### 5️⃣ `setup.sh`: Master Script to Run All

```bash
#!/bin/bash

echo "[*] Starting Secure Ubuntu Server Setup..."

bash scripts/setup-firewall.sh
bash scripts/secure-ssh.sh
bash scripts/install-monitoring.sh
bash scripts/harden-system.sh

echo "[✓] Server secured and ready!"
```

---

## ✅ Outcome

Your server is now:

- Shielded with a UFW firewall  
- Hardened against SSH-based intrusions  
- Monitored for suspicious activity  
- Tuned for better security using AppArmor and sysctl rules  

---

## 📌 Usage

Make all scripts executable:

```bash
chmod +x setup.sh scripts/*.sh
```

Run the master setup:

```bash
./setup.sh
```

---

## 🔐 Recommendation (for AWS EC2 users)

Ensure your **SSH key is copied** to the server **before** disabling password authentication:

```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub ubuntu@your-server-ip
```

---

## 📘 License

MIT License
```

