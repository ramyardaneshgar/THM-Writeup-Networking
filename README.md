# THM-Writeup-Networking
Writeup for TryHackMe Networking Lab - A complete walkthrough of OSI Model &amp; Networking Fundementals.

By Ramyar Daneshgar 


The OSI (Open Systems Interconnection) model is a conceptual framework that defines how different networking protocols interact in a networked system. It consists of seven abstraction layers, each responsible for specific tasks in the end-to-end transmission of data. Understanding each layer in detail is foundational in the field of cybersecurity, especially in areas such as threat modeling, intrusion detection, traffic inspection, and vulnerability exploitation or mitigation. Below is a comprehensive, layer-by-layer breakdown of the OSI Model.

---

**Layer 7: Application Layer**

**Data Unit:** Data  
**Purpose:** This is the topmost layer, directly interfacing with end-user applications. Its primary responsibility is to provide network services to application software.

**Functionality:**
- Supports services such as file transfers (FTP), email (SMTP), remote login (Telnet, SSH), directory services (LDAP), and web browsing (HTTP/HTTPS).
- Facilitates communication between software applications and lower-layer protocols.
- Translates user commands into protocol-level commands.

**Protocols:** HTTP, HTTPS, FTP, TFTP, SMTP, IMAP, POP3, SNMP, DNS, Telnet

**Security Implications:**
- Vulnerable to attacks like SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and buffer overflows.
- Application-level firewalls and Web Application Firewalls (WAFs) protect this layer.
- Requires input validation, session management, secure cookies, and strong authentication mechanisms.

**Real-World Example:** When you type a URL into your browser, the Application Layer initiates an HTTP request to retrieve that webpage.

**Relevant Tools/Commands:**
- `curl` and `wget` for sending HTTP requests.
- `telnet <hostname> 80` to manually craft HTTP requests.
- `nmap -sV` to detect application layer services running on open ports.
- Web vulnerability scanners such as OWASP ZAP and Nikto.

---

**Layer 6: Presentation Layer**

**Data Unit:** Data  
**Purpose:** This layer acts as a translator for data formats, converting data between application and network formats. It also handles encryption and compression.

**Functionality:**
- Ensures data from the application layer is in a standard, interoperable format.
- Responsible for data serialization and deserialization (e.g., converting JSON/XML to byte streams).
- Applies encryption/decryption (SSL/TLS) and compression algorithms.

**Security Implications:**
- Misconfigured or outdated SSL/TLS protocols can be exploited (e.g., Heartbleed).
- Weak ciphers can expose data to cryptographic attacks.
- Compromised or spoofed certificates can lead to man-in-the-middle attacks.

**Real-World Example:** When a secure HTTPS connection is made, SSL/TLS encryption occurs at the Presentation Layer.

**Relevant Tools/Commands:**
- `openssl s_client -connect <host>:443` to inspect SSL/TLS certificates.
- `testssl.sh` or `sslyze` to assess server TLS configurations.
- Browser developer tools to inspect TLS version and certificate details.

---

**Layer 5: Session Layer**

**Data Unit:** Data  
**Purpose:** Manages the sessions (establishment, maintenance, and termination) between applications on different hosts.

**Functionality:**
- Establishes and controls dialog between two systems.
- Maintains session state, synchronization, and dialog control.
- Coordinates when data transfer can begin or resume.

**Security Implications:**
- Sessions can be hijacked or fixed by attackers if not properly secured.
- Requires implementation of session tokens, timeouts, and re-authentication policies.
- Use of secure cookies and HTTPS is essential to protect session data.

**Real-World Example:** Logging into a website starts a session that persists until you log out or the session times out.

**Relevant Tools/Commands:**
- Web proxies like Burp Suite and OWASP ZAP to manipulate session tokens.
- Inspect browser cookies and session headers using browser dev tools.
- Manual tampering with session IDs via tools like Postman or curl.

---

**Layer 4: Transport Layer**

**Data Unit:** Segments (TCP) or Datagrams (UDP)  
**Purpose:** Provides end-to-end communication services for applications. It ensures complete data transfer with error checking and flow control.

**Functionality:**
- Determines whether to use TCP (connection-oriented) or UDP (connectionless).
- Performs segmentation, sequencing, and reassembly of data.
- Provides acknowledgment and retransmission (TCP only).
- Flow control and congestion avoidance mechanisms.

**Protocols:** TCP, UDP, SCTP

**Security Implications:**
- Susceptible to SYN flood (TCP DoS attack), port scanning, and session hijacking.
- Firewalls often operate at this layer to permit or deny traffic based on port numbers.
- Tools like Wireshark and Netcat analyze transport layer traffic.

**Real-World Example:** TCP ensures reliable delivery of a file being downloaded from a server.

**Relevant Tools/Commands:**
- `netstat -an` or `ss -tuln` to check listening ports.
- `nc -lvp <port>` to create TCP/UDP listeners.
- `hping3` for custom packet crafting and TCP flood simulation.
- `wireshark` to capture and inspect TCP/UDP packet flows.

---

**Layer 3: Network Layer**

**Data Unit:** Packets  
**Purpose:** Handles logical addressing, routing, and path determination between source and destination devices across multiple networks.

**Functionality:**
- Adds source and destination IP addresses.
- Determines the best path for packet delivery (via routers).
- Handles packet fragmentation and reassembly.
- Uses ARP to resolve IP addresses to MAC addresses.

**Protocols:** IPv4, IPv6, ICMP, IGMP, OSPF, BGP, RIP

**Security Implications:**
- Vulnerable to IP spoofing, ICMP tunneling, and routing table poisoning.
- Packet filtering firewalls inspect headers at this layer.
- Network ACLs and subnetting strategies mitigate lateral movement in networks.

**Real-World Example:** A router uses the destination IP to forward the packet to the next hop.

**Relevant Tools/Commands:**
- `ping <host>` and `traceroute <host>` to test network reachability.
- `ip addr`, `ip route` to inspect IP and routing info.
- `tcpdump` or `wireshark` for packet-level analysis.
- `nmap -sn <subnet>` for network mapping and host discovery.

---

**Layer 2: Data Link Layer**

**Data Unit:** Frames  
**Purpose:** Provides node-to-node data transfer between devices in the same network and detects/corrects physical layer errors.

**Functionality:**
- Adds source and destination MAC addresses.
- Performs frame synchronization and error detection using checksums.
- Operates in two sublayers: Logical Link Control (LLC) and Media Access Control (MAC).
- Manages access to the physical transmission medium.

**Protocols:** Ethernet (IEEE 802.3), ARP, PPP, VLAN (802.1Q), STP

**Security Implications:**
- ARP spoofing, MAC flooding, and VLAN hopping can compromise this layer.
- Switches and VLANs control broadcast domains.
- Port security and DHCP snooping mitigate common Layer 2 attacks.

**Real-World Example:** A switch reads the destination MAC address in a frame to forward it appropriately.

**Relevant Tools/Commands:**
- `arp -a` to view ARP cache.
- `macchanger` to spoof MAC addresses.
- `ettercap` and `arpspoof` for Layer 2 attacks.
- VLAN configuration and STP monitoring via managed switch CLI or SNMP.

---

**Layer 1: Physical Layer**

**Data Unit:** Bits  
**Purpose:** Concerned with the transmission and reception of raw unstructured data over a physical medium.

**Functionality:**
- Defines electrical, optical, or radio signals for bit transmission.
- Handles physical connections like cables, connectors, voltages, and signal timing.
- Includes NICs, hubs, modems, and network media.

**Standards:** Ethernet (IEEE 802.3), USB, RS-232, DSL, Bluetooth, IEEE 802.11 (Wi-Fi)

**Security Implications:**
- Physical tampering, wiretapping, and hardware-based keyloggers are threats.
- Requires physical access controls (locks, security guards, video surveillance).
- Shielded cabling and electromagnetic interference protections can enhance security.

**Real-World Example:** When you plug an Ethernet cable into your laptop, you’re interacting with the Physical Layer.

**Relevant Tools/Commands:**
- Cable testers (e.g., Fluke testers) to verify physical connectivity.
- RF analyzers to detect Wi-Fi or Bluetooth interference.
- Spectrum analyzers for detecting physical-layer wireless anomalies.
- Physical inspection protocols and environmental security audits.

---

**Conclusion:**

The OSI model provides an indispensable framework for understanding, securing, and troubleshooting networks. For cybersecurity professionals, mastery of each layer enables precise threat detection, root cause analysis, and targeted mitigation strategies. Whether dissecting packet captures, configuring firewalls, or performing penetration testing, a clear understanding of each OSI layer ensures structured and defensible operations in complex enterprise environments.

