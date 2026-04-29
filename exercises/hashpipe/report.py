#!/usr/bin/env python3
import json
from collections import defaultdict
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

# --- CONFIGURATION ---
THRIFT_PORT = 9090
MAX_TABLE_SIZE = 4  # Matches your P4 #define
D = 4                # Stages
TOP_K = 5           # How many top flows we care about detecting

controller = SimpleSwitchThriftAPI(THRIFT_PORT)

def collect_hardware_state():
    """Pulls all registers from the BMv2 data plane."""
    entries = []
    for stage in range(D):
        keys = [controller.register_read(f"key_{stage}", i) for i in range(MAX_TABLE_SIZE)]
        vals = [controller.register_read(f"val_{stage}", i) for i in range(MAX_TABLE_SIZE)]
        for k, v in zip(keys, vals):
            if k != 0:
                entries.append((k, v))
    return entries

def get_hardware_top_k(entries):
    """Merges duplicates (taking the max value) and sorts."""
    merged = defaultdict(int)
    for key, val in entries:
        merged[key] = max(merged[key], val)
    return sorted(merged.items(), key=lambda x: x[1], reverse=True)[:TOP_K]

def evaluate_metrics(hw_top_k, ground_truth_file='ground_truth.json'):
    """Calculates Identification and Estimation Metrics."""
    try:
        with open(ground_truth_file, 'r') as f:
            truth_data = json.load(f)
    except FileNotFoundError:
        print("❌ Error: ground_truth.json not found. Run traffic_generator.py first.")
        return

    # 1. Setup Data Structures
    truth_dict = {item['flow_id']: item['count'] for item in truth_data}
    hw_dict = dict(hw_top_k)

    true_top_k_ids = set(item['flow_id'] for item in truth_data[:TOP_K])
    hw_top_k_ids = set(hw_dict.keys())

    # 2. Calculate Identification Intersections
    true_positives = true_top_k_ids.intersection(hw_top_k_ids)
    false_positives = hw_top_k_ids - true_top_k_ids
    false_negatives = true_top_k_ids - hw_top_k_ids

    tp_count = len(true_positives)
    fp_count = len(false_positives)
    fn_count = len(false_negatives)

    # 3. Calculate Identification Math (F1-Score)
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # 4. Calculate Estimation Accuracy (The "Improvement" Metrics)
    total_relative_error = 0.0
    hw_tp_volume = 0
    gt_tp_volume = 0

    for flow_id in true_positives:
        actual_count = truth_dict[flow_id]
        detected_count = hw_dict[flow_id]
        
        # Relative Error = |Actual - Detected| / Actual
        error = abs(actual_count - detected_count) / actual_count
        total_relative_error += error
        
        hw_tp_volume += detected_count
        gt_tp_volume += actual_count

    avg_relative_error = (total_relative_error / tp_count) if tp_count > 0 else 1.0
    count_accuracy_pct = (1.0 - avg_relative_error) * 100 if tp_count > 0 else 0.0
    
    # Calculate Total Volume Captured
    total_gt_top_k_volume = sum(item['count'] for item in truth_data[:TOP_K])
    total_hw_top_k_volume = sum(count for _, count in hw_top_k)
    volume_capture_pct = (total_hw_top_k_volume / total_gt_top_k_volume) * 100 if total_gt_top_k_volume > 0 else 0.0

    # 5. Print the Report
    print("\n" + "="*60)
    print("ENHANCED HASHPIPE EVALUATION REPORT")
    print("="*60)
    
    print("\n[ Hardware State vs. Ground Truth ]")
    print(f"{'Rank':<6} | {'Hardware Detected':<22} | {'Ground Truth (Actual)':<22}")
    print("-" * 60)
    
    for i in range(TOP_K):
        hw_str = f"{hw_top_k[i][0]} ({hw_top_k[i][1]})" if i < len(hw_top_k) else "N/A"
        gt_str = f"{truth_data[i]['flow_id']} ({truth_data[i]['count']})" if i < len(truth_data) else "N/A"

        print(f"{i+1:<4} | {hw_str:<22} | {gt_str:<22}")

    print("\n[ Phase 1: Identification Metrics ]")
    print(f"True Positives  : {tp_count}")
    print(f"False Positives : {fp_count}")
    print(f"False Negatives : {fn_count}")
    print("-" * 60)
    print(f"Precision       : {precision:.4f}")
    print(f"Recall          : {recall:.4f}")
    print(f"F1-Score        : {f1_score:.4f}")

    print("\n[ Phase 2: Estimation & Volume Metrics ]")
    print(f"Avg Relative Error (ARE) : {avg_relative_error:.4f} (Lower is better)")
    print(f"Count Accuracy (TPs)     : {count_accuracy_pct:.2f}% (Higher is better)")
    print(f"Top-K Volume Captured    : {volume_capture_pct:.2f}% of heavily-hit traffic")
    print("="*60 + "\n")

if __name__ == "__main__":
    print("📡 Reading HashPipe hardware registers...")
    hw_entries = collect_hardware_state()
    hw_top_k = get_hardware_top_k(hw_entries)
    evaluate_metrics(hw_top_k)
