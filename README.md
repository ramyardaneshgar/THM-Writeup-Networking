# THM-Writeup-Networking
**By Ramyar Daneshgar**

The OSI (Open Systems Interconnection) model is a conceptual framework that defines how different networking protocols interact in a networked system. It consists of seven abstraction layers, each responsible for specific tasks in the end-to-end transmission of data. Understanding each layer in detail is foundational in the field of cybersecurity, especially in areas such as threat modeling, intrusion detection, traffic inspection, and vulnerability exploitation or mitigation.

---

**Layer 7: Application Layer**

**Data Unit:** Data  
**Purpose:** Interfaces directly with user-facing applications and provides network services to software.

**Functionality:**
- Supports services such as file transfers, email, remote login, and web browsing.
- Facilitates communication between software and lower-layer protocols.
- Translates user commands into protocol-level instructions.

**Protocols:** HTTP, HTTPS, FTP, TFTP, SMTP, IMAP, POP3, SNMP, DNS, Telnet

**Security Implications:**
- Vulnerable to SQL Injection, Cross-Site Scripting, CSRF, buffer overflows.
- Web Application Firewalls (WAFs) mitigate threats at this layer.
- Requires input validation, session management, secure cookies, and proper authentication.

**Relevant Tools/Commands:**
- `curl`, `wget` for HTTP requests  
- `telnet <hostname> 80` to craft requests manually  
- `nmap -sV` for service enumeration  
- OWASP ZAP, Nikto for application-layer scanning

---

**Layer 6: Presentation Layer**

**Data Unit:** Data  
**Purpose:** Translates data formats, applies encryption and compression.

**Functionality:**
- Converts application-layer data into a network-compatible format.
- Manages data serialization/deserialization and secure transmission.
- Applies encryption and decryption mechanisms.

**Security Implications:**
- Susceptible to cryptographic attacks, misconfigured SSL/TLS, weak cipher suites.
- Exploitable via attacks like Heartbleed or protocol downgrades.

**Relevant Tools/Commands:**
- `openssl s_client -connect <host>:443` for TLS inspection  
- `testssl.sh`, `sslyze` for auditing server SSL configurations  
- Browser dev tools for real-time certificate inspection

---

**Layer 5: Session Layer**

**Data Unit:** Data  
**Purpose:** Manages logical sessions between communicating hosts.

**Functionality:**
- Establishes, maintains, and terminates sessions.
- Ensures persistent connections across requests.
- Handles session identifiers and synchronization.

**Security Implications:**
- Targeted in session hijacking, fixation, and replay attacks.
- Secured via HTTPS, token management, cookie flags, and timeouts.

**Relevant Tools/Commands:**
- Burp Suite, OWASP ZAP for session token manipulation  
- Dev tools for cookie/session inspection  
- Postman or curl for custom session testing

---

**Layer 4: Transport Layer**

**Data Unit:** Segments (TCP), Datagrams (UDP)  
**Purpose:** Ensures reliable or fast transport of data between endpoints.

**Functionality:**
- Uses TCP for reliable, connection-oriented delivery.
- Uses UDP for faster, connectionless communication.
- Handles segmentation, error checking, and flow control.

**Protocols:** TCP, UDP, SCTP

**Security Implications:**
- Vulnerable to SYN flooding, port scanning, TCP RST injection.
- Firewalls and intrusion detection systems monitor this layer closely.

**Relevant Tools/Commands:**
- `netstat -an`, `ss -tuln` for socket inspection  
- `nc -lvp <port>` for TCP/UDP listener setup  
- `hping3` for crafted packet injection  
- `wireshark`, `tcpdump` for traffic analysis

---

**Layer 3: Network Layer**

**Data Unit:** Packets  
**Purpose:** Performs logical addressing and routes data across networks.

**Functionality:**
- Adds IP addresses, determines best path via routing protocols.
- Fragments and reassembles packets.
- Uses ARP to resolve Layer 3 to Layer 2 addresses.

**Protocols:** IPv4, IPv6, ICMP, OSPF, BGP, RIP

**Security Implications:**
- Subject to IP spoofing, ICMP tunneling, and route manipulation.
- Firewall rules and ACLs operate here for network segmentation and access control.

**Relevant Tools/Commands:**
- `ping`, `traceroute` for network diagnostics  
- `ip addr`, `ip route` to view configurations  
- `tcpdump`, `wireshark` for packet inspection  
- `nmap -sn <subnet>` for host discovery

---

**Layer 2: Data Link Layer**

**Data Unit:** Frames  
**Purpose:** Responsible for node-to-node transfer and physical addressing.

**Functionality:**
- Adds MAC addresses for devices on the same network segment.
- Performs checksum-based error detection.
- Handles access to the physical medium.

**Protocols:** Ethernet, ARP, VLAN, PPP, STP

**Security Implications:**
- Prone to ARP spoofing, MAC flooding, VLAN hopping.
- Mitigated with port security, DHCP snooping, dynamic ARP inspection.

**Relevant Tools/Commands:**
- `arp -a` to view ARP cache  
- `macchanger` to spoof MAC addresses  
- `ettercap`, `arpspoof` for Layer 2 attacks  
- Managed switch CLI for VLAN and STP configs

---

**Layer 1: Physical Layer**

**Data Unit:** Bits  
**Purpose:** Defines hardware-level signal transmission.

**Functionality:**
- Transmits bits via electrical, optical, or radio means.
- Involves cabling, modems, NICs, antennas.
- Defines physical standards and topologies.

**Standards:** Ethernet, USB, RS-232, DSL, Bluetooth, Wi-Fi

**Security Implications:**
- Susceptible to hardware tampering, jamming, wiretapping.
- Countermeasures include CCTV, cable locks, and physical separation.

**Relevant Tools/Commands:**
- Cable testers (e.g., Fluke), signal analyzers  
- RF analyzers for wireless spectrum monitoring  
- Physical inspections and datacenter access policies

---

## Conclusion

The OSI model is not just a theoretical construct but a critical foundation for all modern cybersecurity operations. Mastery of each layer allows professionals to better understand how attackers operate, how systems communicate, and where defenses must be applied. This document provides both theoretical insight and practical tooling for every layer, making it a strong base for penetration testing, threat hunting, defensive engineering, or compliance auditing.

