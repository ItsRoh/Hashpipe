import time
import random
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from collections import defaultdict

THRIFT_PORT = 9090
MAX_TABLE_SIZE = 4
D = 4                
TOP_K = 5

controller = SimpleSwitchThriftAPI(THRIFT_PORT)

def initialize_adaptive_pipeline():
    print("⚙️  Pushing Initial HashPipe Configuration...")
    controller.register_write("seed_reg_0", 0, 101)
    controller.register_write("seed_reg_1", 0, 202)
    controller.register_write("seed_reg_2", 0, 303)
    controller.register_write("seed_reg_3", 0, 404)  
    
    controller.register_write("stage_enable_reg", 0, 15)
    controller.register_write("evict_thresh_reg", 0, 0)

def read_registers(reg_name):
    """Read entire register array"""
    values = []
    for i in range(MAX_TABLE_SIZE):
        val = controller.register_read(reg_name, i)
        values.append(val)
    return values

def collect_all_stages():
    """Collect keys and values from all pipeline stages"""
    all_entries = []
    for stage in range(D):
        key_reg = f"key_{stage}"
        val_reg = f"val_{stage}"
        keys = read_registers(key_reg)
        vals = read_registers(val_reg)
        for i in range(MAX_TABLE_SIZE):
            all_entries.append((keys[i], vals[i]))
    return all_entries

def merge_duplicates(entries):
    """Merge duplicate flow entries across stages"""
    merged = defaultdict(int)
    for key, val in entries:
        if key != 0: # Ignore empty slots to clean up output
            merged[key] += val
    return merged

def get_top_k(merged_flows, k=TOP_K):
    """Return top-k heavy flows"""
    sorted_flows = sorted(merged_flows.items(),
                          key=lambda x: x[1],
                          reverse=True)
    return sorted_flows[:k]

def print_hashpipe_tables(entries):
    """Prints the raw pipeline registers column by column"""
    print("\n📡 Reading HashPipe registers...")
    sachin = []
    for i in range(D):
        rohit = []
        for j in range(MAX_TABLE_SIZE):
            rohit.append(entries[MAX_TABLE_SIZE*i+j])
        sachin.append(rohit)
        
    print(f"{'Stage 0':<15} {'Stage 1':<15} {'Stage 2':<15} {'Stage 3':<15}")
    print("-" * 60)
    for col in zip(*sachin):
        print("     ".join(f"[{x:<3},{y:>2}]" for x, y in col))

def print_top_k(top_flows):
    print("\n🔥 Top Heavy Flows:")
    print("FlowID\t\tCount")
    print("-" * 30)
    for flow, count in top_flows:
        print(f"{flow}\t\t{count}")

def read_and_reset_telemetry():
    """Reads telemetry, calculates rates, and resets P4 registers"""
    pkt_cnt = controller.register_read("packet_counter", 0)
    coll_cnt = controller.register_read("collision_counter", 0)
    ev_cnt = controller.register_read("eviction_counter", 0)

    # Calculate Rates
    collision_rate = (coll_cnt / pkt_cnt) if pkt_cnt > 0 else 0.0
    eviction_rate = (ev_cnt / pkt_cnt) if pkt_cnt > 0 else 0.0

    # Reset Counters (Crucial)
    controller.register_write("packet_counter", 0, 0)
    controller.register_write("collision_counter", 0, 0)
    controller.register_write("eviction_counter", 0, 0)

    return pkt_cnt, collision_rate, eviction_rate

def apply_adaptive_rules(collision_rate, eviction_rate):
    """Executes the 4 dynamic strategies based on real-time metrics"""
    
    # RULE 1: Adaptive Hash Functions
    if collision_rate > 5: 
        print(" 🔴 HIGH COLLISIONS -> Rotating Hash Seeds")
        controller.register_write("seed_reg_0", 0, random.randint(1000, 10000))
        controller.register_write("seed_reg_1", 0, random.randint(1000, 10000))
        controller.register_write("seed_reg_2", 0, random.randint(1000, 10000))
        controller.register_write("seed_reg_3", 0, random.randint(1000, 10000))

    # RULE 2: Adaptive Stage Depth
    if eviction_rate > 0.2:
        print(" 🔵 HIGH EVICTIONS -> Enabling all 4 stages")
        controller.register_write("stage_enable_reg", 0, 15) # 0b1111
    elif eviction_rate < 0.01:
        print(" 🟢 LOW EVICTIONS -> Bypassing Stage 3 to save resources")
        controller.register_write("stage_enable_reg", 0, 7)  # 0b0111

    # RULE 3: Adaptive Eviction Policy
    if collision_rate > 1.0 and eviction_rate > 0.15:
        print(" 🔊 NOISE DETECTED -> Increasing eviction threshold")
        controller.register_write("evict_thresh_reg", 0, 5)
    else:
        print(" 🔇 TRAFFIC STABLE -> Lowering eviction threshold")
        controller.register_write("evict_thresh_reg", 0, 0)

def start_adaptive_loop(interval=3):
    """Continuous background loop for SDN monitoring"""
    print(f"\n🔁 Starting Adaptive Control Loop (Interval: {interval}s)")
    while True:
        try:
            time.sleep(interval)
            
            # 1. Read HashPipe Tables and Top-K
            entries = collect_all_stages()
            print_hashpipe_tables(entries)
            
            merged = merge_duplicates(entries)
            top_flows = get_top_k(merged)
            print_top_k(top_flows)
            
            # 2. Process Telemetry
            pkt_cnt, coll_rate, ev_rate = read_and_reset_telemetry()
            
            if pkt_cnt == 0:
                print("\n⏳ Waiting for traffic...")
                continue
                
            print(f"\n📊 [Telemetry Window] Packets: {pkt_cnt} | Collisions/Pkt: {coll_rate:.2f} | Eviction Rate: {ev_rate:.2%}")
            
            # 3. Trigger the adaptive changes
            apply_adaptive_rules(coll_rate, ev_rate)
            
        except KeyboardInterrupt:
            print("\n🛑 Terminating Adaptive Loop.")
            break

def main():
    initialize_adaptive_pipeline()
    start_adaptive_loop(interval=3)

if __name__ == "__main__":
    main()
