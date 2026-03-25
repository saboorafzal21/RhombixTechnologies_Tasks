# RhombixTechnologies_Tasks
# Basic Network Sniffer (Python)

## Overview
This project is a Python-based network sniffer developed using Scapy. It captures and analyzes network traffic in real time.

## ⚙️ Features
- Captures live network packets
- Displays source & destination IP
- Detects protocols (TCP, UDP, ICMP)
- Extracts port numbers
- Filters HTTP/HTTPS traffic (Port 80 & 443)
- Detects suspicious ports (21, 22, 23, 4444)
- Logs all traffic with timestamps
- Optional GUI interface

## Technologies Used
- Python
- Scapy
- Tkinter (for GUI)

## How to Run
1. Install dependencies:
   pip install scapy

2. Run script:
   python sniffer.py

##  Output
- Live packet capture in terminal
- Log file saved as `log.txt`

## Learning Outcome
This project helped in understanding:
- Network packet structure
- Protocol analysis
- Real-time traffic monitoring
- Basic intrusion detection concepts
