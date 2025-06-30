# Post-Quantum Nginx Setup Script for Ubuntu 24

This script automates the process of setting up Nginx with post-quantum cryptography support on Ubuntu 24. It integrates quantum-resistant algorithms for securing communications, preparing the system for the emerging challenges posed by quantum computing.

## Features

- Installs Nginx on Ubuntu 24
- Configure Openssl version 3.5.0
- Configures Nginx to use post-quantum cryptographic algorithms.
- Updates SSL/TLS settings to support post-quantum standards.
- Configures Quantum-Resistant Key Exchange (KEX) using Post-Quantum algorithms.
- Automatically sets up certificates for secure communication.

## Prerequisites

- Ubuntu 24
- Root or sudo privileges on the machine.
- A working internet connection.

## Installation

```bash
git clone https://github.com/DivyanshGohil/pqc-server.git
cd pqc-server
chmod +x pqc-install.sh
sudo ./pqc-install.sh
```

## Important Points

- NGINX is installed at **/opt/nginx**
- OpenSSL is installed at **/opt/bin/openssl**
- Status log file location: **/var/log/pqc_install_status.log**
- To verify post-quantum TLS, open **https://{ip}/pqc-example.com/** in a browser that supports post-quantum key exchange. Verify it using wireshark
- By Default we use **X25519MLKEM768** hybrid kex exchange.
- To use openssl 3.5.0 version add **export PATH=/opt/bin:$PATH** line to **~/.bashrc** file