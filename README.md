# Overview #
BrainHack CDDC 2024 (A Jeopardy-style Capture-The-Flag (CTF) competition)

Repository to store my team's answers for CDDC 2024

## Disclaimer ##
This repo will be used to track all tools and python codes used for the competition.

# Tools Used #

## OSINT (Open Source Intelligence)

### Sherlock
- **Description:** Sherlock is a powerful tool written in Python that helps find usernames across various social media platforms. By providing a username, Sherlock checks numerous websites to see if the username exists on those platforms.
- **Usage:** `python sherlock username`

## Network Category

### Wireshark
- **Description:** Wireshark is a widely-used network protocol analyzer for capturing and analyzing network traffic. It allows you to examine data from a live network or from a capture file on disk.
- **Usage:** Download and install Wireshark from the [official website](https://www.wireshark.org/), then open capture files (pcap) for analysis.

### aPackets
- **Description:** aPackets is a PCAP visualizer that provides a graphical representation of network traffic. It helps identify suspicious servers and IPs, making it useful for network analysis and security investigations.
- **Usage:** Access aPackets via the [website](https://apackets.com/) and upload your PCAP file for visualization and analysis.

## Cryptography

### DCODE Website
- **Description:** DCODE is an online platform offering a variety of cryptographic tools and solvers. It supports encoding, decoding, and solving various types of ciphers, making it a versatile tool for cryptography challenges.
- **Usage:** Access the tools via the [DCODE website](https://www.dcode.fr/).

## Forensics

### Volatility 3
- **Description:** Volatility 3 is an advanced memory forensics framework that analyzes memory dumps to extract valuable forensic information. It helps investigators understand what was happening on a system at the time the memory was captured.
- **Usage:** Suitable for analyzing `.mem` memory dump files.

## Binary Exploitation

### GDB with PEDA
- **Description:** GDB (GNU Debugger) is a powerful debugging tool for programs written in C, C++, and other languages. PEDA (Python Exploit Development Assistance for GDB) enhances GDB by adding a range of useful features for exploit development.
- **Usage:** Use `gdb` commands with PEDA for debugging and exploit development.

### Radare2
- **Description:** Radare2 is a highly versatile open-source framework for reverse engineering and analyzing binaries. It supports various architectures and file formats, making it a valuable tool for binary exploitation.
- **Usage:** Commands are executed within the radare2 interface for tasks such as disassembly, debugging, and analysis.

### scdbg
- **Description:** scdbg (Shellcode Debugger) is a tool used for analyzing shellcode. It emulates shellcode execution, providing insights into its behavior, which is essential for understanding and developing exploits.
- **Usage:** Run shellcode within scdbg to analyze its behavior and debug any issues.

### Ghidra
- **Description:** Ghidra is a comprehensive open-source software reverse engineering (SRE) suite developed by the National Security Agency (NSA). It includes a variety of features for analyzing compiled code on multiple platforms.
- **Usage:** Use Ghidra's graphical interface and tools to disassemble, decompile, and analyze binary files.

## Web Exploitation

### RsaCtfTool
- **Description:** RsaCtfTool is a specialized program for attacking RSA encryption. It includes multiple methods for breaking weak RSA keys, making it a valuable tool for CTF competitions and real-world security assessments.
- **Usage:** Use the tool's various attack modes to exploit vulnerabilities in RSA implementations.
