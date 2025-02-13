# Hybrid Intrusion Detection System (IDS)

An Intrusion Detection System (IDS) is like a security camera for your network. Just as security cameras help identify suspicious activities in the physical world, an IDS monitors your network to detect potential cyber attacks and security breaches.

## Overview

This project provides a step-by-step guide to building your own real-time network monitoring system using Python. The IDS combines signature-based and anomaly-based detection methods to analyze network traffic.

## Features

- Real-time packet capturing using Scapy
- Traffic analysis module to extract relevant network features
- Hybrid detection engine with:
  - Signature-based detection for known attack patterns
  - Anomaly-based detection using Machine Learning (Isolation Forest)
- Alert system for logging detected threats

## Installation

Ensure you have Python 3 installed, then install the required dependencies:

```sh
pip install scapy python-nmap numpy sklearn
```

## Usage

To start the IDS, simply run:

```sh
python-ids.py
```

By default, it monitors the `eth0` interface. Modify the script to change the network interface based on your system.

## Components

1. **Packet Capture Engine**: Captures network packets using Scapy.
2. **Traffic Analysis Module**: Extracts features such as packet size, TCP flags, and byte rate.
3. **Detection Engine**:
   - Signature-based detection for predefined attack patterns.
   - Anomaly detection using Isolation Forest.
4. **Alert System**: Logs alerts and potential threats with details.

## Testing

To validate the IDS, test it with mock data:

```sh
python test_ids.py
```

This script simulates different attack scenarios like SYN flooding and port scanning.

## Ideas to Extend

- Improve anomaly detection using deep learning models.
- Optimize performance using parallel processing.
- Integrate with SIEM systems for enterprise monitoring.
- Implement real-time notifications via Slack or email.

## Security Considerations

- Requires admin/root privileges for packet capture.
- Secure alert logs and implement proper log rotation.
- Update signature rules and retrain models regularly.
- Monitor system resource usage in high-traffic environments.

## License

This project is licensed under the MIT License. Feel free to modify and improve!
