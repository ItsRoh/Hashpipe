#!/usr/bin/env python3

from scapy.all import *
import time

# -------- CONFIG --------
TARGET_IP = "10.0.1.1"

flows = [
    ("10.0.1.2", TARGET_IP, 200),
    ("10.0.1.3", TARGET_IP, 300),
    ("10.0.1.4", TARGET_IP, 400),
    ("10.0.1.5", TARGET_IP, 500),
]

BATCH_SIZE = 100   # 🔥 key change

print("🚀 Generating batched interleaved traffic...\n")

# Track packets sent per flow
sent_counts = [0] * len(flows)

# Continue until all flows finish
while any(sent_counts[i] < flows[i][2] for i in range(len(flows))):

    for i, (src, dst, total) in enumerate(flows):

        remaining = total - sent_counts[i]
        if remaining <= 0:
            continue

        # send up to 100 packets at once
        batch = min(BATCH_SIZE, remaining)

        print(f"Flow {i}: {src} → {dst} | Sending {batch} packets")

        for _ in range(batch):
            pkt = Ether() / IP(src=src, dst=dst) / TCP(dport=80, sport=10000+i)
            sendp(pkt, iface="eth0", verbose=0)

        sent_counts[i] += batch

    time.sleep(0.01)  # small gap between rounds

print("\n📊 Flow Summary:")
for i, (src, dst, total) in enumerate(flows):
    print(f"Flow {i}: {src} → {dst} | Packets: {total}")

print("\n✅ Traffic generation complete!")
