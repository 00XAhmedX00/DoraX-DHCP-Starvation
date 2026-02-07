# DoraX – DHCP Starvation Tool

**Author:** Ahmed Mohamed (X_ByteBandit_X)  
**Version:** 1.0

---

## ⚠️ Disclaimer

This project is created **for educational purposes and authorized security testing only**.

Running DHCP starvation attacks on networks **without explicit written permission** is illegal and unethical. The author is **not responsible for any misuse or damage** caused by this tool.

Use this tool **only in labs, CTF environments, or networks you own or are authorized to test**.

---

## 📌 Overview

**DoraX** is a multithreaded DHCP starvation testing tool built with **Python** and **Scapy**.

It simulates multiple DHCP clients by generating **random MAC addresses** and sending DHCP **DISCOVER → REQUEST** sequences in parallel threads to exhaust the DHCP server’s IP lease pool.

This helps security students and penetration testers:

- Understand DHCP starvation attacks
- Test DHCP server resilience
- Practice detection and mitigation techniques

---

## 🚀 Features

- Multithreaded DHCP starvation simulation
- Random MAC address generation per thread
- Automatic DHCP OFFER → REQUEST → ACK handling
- Timeout control for each request
- Lightweight and fast execution

---

## 🧰 Requirements

- Python **3.8+**
- Linux environment (recommended: Kali Linux or Ubuntu)
- Root / sudo privileges
- Installed dependencies:

```bash
pip install scapy
```

---

## ⚙️ Configuration

Before running the tool, edit the network interface inside the script:

```python
iface = "eth0"  # Change to your interface
```

To list available interfaces:

```bash
ip a
```

---

## ▶️ Usage

Run with root privileges:

```bash
sudo python3 dorax.py
```

Enter the number of starvation requests when prompted.

Example:

```text
Enter Number of Starvation Requests: 50
```

---

## 🧪 Recommended Lab Setup

Use only in a **controlled lab**, for example:

- Attacker: Kali Linux VM
- Target DHCP Server: Router VM or Windows Server DHCP role
- Isolated virtual network (VirtualBox / VMware / GNS3 / EVE‑NG)

---

## 🛡️ Detection & Mitigation (For Defenders)

Security teams can protect against DHCP starvation using:

- **DHCP Snooping** on switches
- **Port security** (limit MAC addresses per port)
- **Rate limiting** DHCP requests
- **Network monitoring / SIEM alerts**

---

## 📚 Educational Purpose

This project is useful for:

- Cybersecurity students
- Penetration testing beginners
- Network security labs
- CTF preparation

---

## 📄 License

MIT License – free to use for learning and research.

---

## 🤝 Contributing

Pull requests and improvements are welcome.

If you find a bug or want a new feature, open an **issue** on GitHub.

---

## ⭐ Support

If you like this project, consider giving it a **star** on GitHub to support future security tools and research.

---

**Stay ethical. Hack responsibly.**

