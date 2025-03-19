# Hybrid Intrusion Detection System (IDS)

An Intrusion Detection System (IDS) is like a security camera for your network. Just as security cameras help identify suspicious activities in the physical world, an IDS monitors your network to detect potential cyberattacks and security breaches.

## Overview

This project provides a step-by-step guide to building your own real-time network monitoring system using Python. The IDS combines signature-based and anomaly-based detection methods to analyze network traffic and detect potential threats.

## Features

- **Real-time packet capturing** using Scapy  
- **Traffic analysis module** to extract relevant network features  
- **Hybrid detection engine** with:  
  - Signature-based detection for known attack patterns  
  - Anomaly-based detection using Machine Learning (Isolation Forest)  
- **Alert system** for logging detected threats  
- **User-configurable network interface selection**  

## Installation

Ensure you have **Python 3** installed, then install the required dependencies:

```sh
pip install scapy python-nmap numpy scikit-learn
```

## Usage

To start the IDS, simply run:

```sh
python ids.py
```

You will be prompted to enter a network interface (e.g., `eth0` or `wlan0`). If left blank, it defaults to `eth0`.  
Modify the script if needed to change the default interface.

## Components

1. **Packet Capture Engine**  
   - Captures network packets in real time using Scapy.  
   - Uses a queue to store packets for processing.  

2. **Traffic Analysis Module**  
   - Extracts network flow features, including packet size, TCP flags, byte rate, and more.  
   - Keeps track of ongoing network flows and updates statistics dynamically.  

3. **Detection Engine**  
   - **Signature-based detection**: Detects predefined attack patterns like SYN floods and port scans.  
   - **Anomaly detection**: Uses an **Isolation Forest** model trained on normal traffic patterns to detect unusual activity.  

4. **Alert System**  
   - Logs alerts to `ids_alerts.log` with timestamps, confidence levels, and attack details.  
   - High-confidence threats trigger **critical alerts**.  

## Training the Anomaly Detection Model

The IDS **collects normal traffic samples** at startup to train the Isolation Forest model.  
- It captures **100 normal traffic samples** before beginning anomaly detection.  
- If insufficient data is collected, a warning is displayed, and anomaly detection may be less accurate.  

## Testing

To validate the IDS, test it with mock attack scenarios:

```sh
python test_ids.py
```

This script simulates different attack behaviors such as **SYN flooding** and **port scanning** to verify detection accuracy.

## Ideas to Extend

- **Improve anomaly detection** with deep learning models.  
- **Optimize performance** using parallel processing.  
- **Integrate with SIEM systems** for enterprise-level monitoring.  
- **Implement real-time alerts** via Slack, email, or webhook notifications.  

## Security Considerations

- Requires **admin/root privileges** for packet capture.  
- Ensure **secure log storage** and implement proper log rotation.  
- Regularly **update signature rules** and retrain the anomaly model.  
- Monitor **system resource usage** in high-traffic environments.  

## License

This project is licensed under the **MIT License**. Feel free to modify and improve! 🚀
