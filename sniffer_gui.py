import tkinter as tk
from scapy.all import sniff
from datetime import datetime
import threading

def start_sniffing():
    def packet_callback(packet):
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]

            protocol = "Other"
            if packet.haslayer("TCP"):
                protocol = "TCP"
            elif packet.haslayer("UDP"):
                protocol = "UDP"

            log = f"{datetime.now()} | [{protocol}] {ip_layer.src} -> {ip_layer.dst}\n"
            
            text_area.insert(tk.END, log)
            text_area.see(tk.END)

    sniff(prn=packet_callback, store=False, count=50)

def run_sniffer():
    thread = threading.Thread(target=start_sniffing)
    thread.start()

# GUI setup
root = tk.Tk()
root.title("Network Sniffer")

text_area = tk.Text(root, height=20, width=80)
text_area.pack()

start_button = tk.Button(root, text="Start Sniffing", command=run_sniffer)
start_button.pack()

root.mainloop()