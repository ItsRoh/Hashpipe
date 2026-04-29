from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from collections import defaultdict

THRIFT_PORT = 9090
TABLE_SIZE = 4
D = 4   # number of stages
TOP_K = 5

controller = SimpleSwitchThriftAPI(THRIFT_PORT)


def read_registers(reg_name):
    """Read entire register array"""
    values = []
    for i in range(TABLE_SIZE):
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

        for i in range(TABLE_SIZE):
            if keys[i] != 0:
                all_entries.append((keys[i], vals[i]))

    return all_entries

def print_hashpipe_tables(entries):
    """Prints the raw pipeline registers column by column"""
    sachin = []
    for i in range(D):
        rohit = []
        for j in range(TABLE_SIZE):
            rohit.append(entries[TABLE_SIZE*i+j])
        sachin.append(rohit)
        
    print(f"{'Stage 0':<15} {'Stage 1':<15} {'Stage 2':<15} {'Stage 3':<15}")
    print("-" * 60)
    for col in zip(*sachin):
        print("     ".join(f"[{x:<3},{y:>2}]" for x, y in col))

def merge_duplicates(entries):
    """Merge duplicate flow entries across stages"""
    merged = defaultdict(int)

    for key, val in entries:
        merged[key] += val

    return merged


def get_top_k(merged_flows, k=TOP_K):
    """Return top-k heavy flows"""
    sorted_flows = sorted(merged_flows.items(),
                          key=lambda x: x[1],
                          reverse=True)
    return sorted_flows[:k]


def print_top_k(top_flows):
    print("\n🔥 Top Heavy Flows:")
    print("FlowID\t\tCount")
    print("-" * 30)
    for flow, count in top_flows:
        print(f"{flow}\t\t{count}")


def main():
    print("Reading HashPipe registers...")

    entries = collect_all_stages()
    print_hashpipe_tables(entries)
    merged = merge_duplicates(entries)
    top_flows = get_top_k(merged)

    print_top_k(top_flows)


if __name__ == "__main__":
    main()
