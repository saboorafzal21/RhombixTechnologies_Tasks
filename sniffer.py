from scapy.all import sniff
from datetime import datetime

# Suspicious ports list
SUSPICIOUS_PORTS = [21, 22, 23, 4444]

def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]

        protocol = "Other"
        src_port = ""
        dst_port = ""
        alert = ""

        # Detect protocol + ports
        if packet.haslayer("TCP"):
            protocol = "TCP"
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport

            # Suspicious detection
            if dst_port in SUSPICIOUS_PORTS:
                alert = "⚠️ SUSPICIOUS PORT"

        elif packet.haslayer("UDP"):
            protocol = "UDP"
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport

        elif packet.haslayer("ICMP"):
            protocol = "ICMP"

        # Create log
        log = f"{datetime.now()} | [{protocol}] {ip_layer.src}:{src_port} -> {ip_layer.dst}:{dst_port} {alert}"

        print(log)

        # Save to file
        with open("log.txt", "a") as f:
            f.write(log + "\n")


# Start sniffing (filtered traffic)
sniff(prn=packet_callback, store=False, filter="tcp port 80 or tcp port 443", count=50)