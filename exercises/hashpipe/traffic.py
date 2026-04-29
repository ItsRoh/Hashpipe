#!/usr/bin/env python3
import json
import struct
import socket
import zlib
import time
import random
import argparse
import numpy as np
from collections import Counter
from scapy.all import Ether, IP, UDP, sendp

IFACE = "eth0"

def calculate_p4_hash(src_ip, dst_ip, protocol=17):
    """Replicates the BMv2 CRC32 hash exactly."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    proto_byte = struct.pack('!B', protocol)
    data = src_bytes + dst_bytes + proto_byte
    return zlib.crc32(data) & 0xffffffff

def save_ground_truth(ground_truth):
    top_flows = [{'flow_id': k, 'count': v} for k, v in ground_truth.most_common()]
    with open('ground_truth.json', 'w') as f:
        json.dump(top_flows, f, indent=4)
    print(f"✅ Traffic complete. Ground truth saved to 'ground_truth.json'.")

def generate_zipfian():
    print("🚀 Generating [ZIPFIAN] Datacenter Traffic...")
    NUM_FLOWS = 400
    TOTAL_PACKETS = 3000
    ZIPF_ALPHA = 1.5 
    
    ground_truth = Counter()
    weights = np.array([1.0 / (i + 1)**ZIPF_ALPHA for i in range(NUM_FLOWS)])
    weights /= weights.sum()
    
    flows = [(f"10.0.{(i // 250) % 256}.{(i % 250) + 1}", "10.0.0.1") for i in range(NUM_FLOWS)]
    sequence = np.random.choice(range(NUM_FLOWS), size=TOTAL_PACKETS, p=weights)
    
    for idx in sequence:
        src_ip, dst_ip = flows[idx]
        flow_hash = calculate_p4_hash(src_ip, dst_ip)
        ground_truth[flow_hash] += 1
        
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst=dst_ip) / UDP(sport=1000, dport=80)
        sendp(pkt, iface=IFACE, verbose=False)
        
    save_ground_truth(ground_truth)

def generate_bursty():
    print("🚀 Generating [BURSTY] Temporal Traffic...")
    ground_truth = Counter()
    
    # Burst 1: Early Elephants (They will become stale)
    print("📡 Sending Early Burst...")
    for i in range(5):
        src_ip = f"11.0.0.{i+1}"
        flow_hash = calculate_p4_hash(src_ip, "10.0.0.1")
        ground_truth[flow_hash] += 300
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=1000, dport=80)
        for _ in range(300): sendp(pkt, iface=IFACE, verbose=False)
        
    # Mice Noise to trigger time delay
    print("⏳ Delay and Mice noise...")
    for i in range(500):
        src_ip = f"172.16.0.{(i % 250) + 1}"
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=1000, dport=80)
        sendp(pkt, iface=IFACE, verbose=False)
    time.sleep(3.5) # Allow SDN controller to poll
        
    # Burst 2: Late Elephants (Static will bounce them off Burst 1)
    print("🐘 Sending Late Burst...")
    for i in range(5):
        src_ip = f"12.0.0.{i+1}"
        flow_hash = calculate_p4_hash(src_ip, "10.0.0.1")
        ground_truth[flow_hash] += 400
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=1000, dport=80)
        for _ in range(400): sendp(pkt, iface=IFACE, verbose=False)

    save_ground_truth(ground_truth)

def generate_ddos():
    print("🚀 Generating [DDOS] Botnet Attack...")
    ground_truth = Counter()
    traffic_sequence = []

    # 1. The True Legitimate Elephants
    for i in range(10):
        src_ip = f"11.0.0.{i+1}"
        flow_hash = calculate_p4_hash(src_ip, "10.0.0.1")
        ground_truth[flow_hash] += 250
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=1000, dport=80)
        traffic_sequence.extend([pkt] * 250)

    # 2. The Botnet (High volume of 15-packet flows to evict Elephants)
    for i in range(400):
        src_ip = f"192.168.{(i // 250) % 256}.{(i % 250) + 1}"
        flow_hash = calculate_p4_hash(src_ip, "10.0.0.1")
        ground_truth[flow_hash] += 15
        pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=1000, dport=80)
        traffic_sequence.extend([pkt] * 15)

    random.shuffle(traffic_sequence)
    
    print(f"📡 Injecting {len(traffic_sequence)} mixed packets...")
    for pkt in traffic_sequence:
        sendp(pkt, iface=IFACE, verbose=False)

    save_ground_truth(ground_truth)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HashPipe Traffic Generator")
    parser.add_argument("--mode", choices=["zipfian", "bursty", "ddos"], required=True, help="Traffic profile to generate")
    args = parser.parse_args()

    if args.mode == "zipfian":
        generate_zipfian()
    elif args.mode == "bursty":
        generate_bursty()
    elif args.mode == "ddos":
        generate_ddos()
