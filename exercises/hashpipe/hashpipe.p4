#include <core.p4>
#include <v1model.p4>

/* ================= CONFIG ================= */
#define D 4                 
#define MAX_TABLE_SIZE 32 

typedef bit<32> ip_t;

/* ================= HEADERS ================= */

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> ethType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> len;
    bit<16> id;
    bit<3>  flags;
    bit<13> frag;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    ip_t srcAddr;
    ip_t dstAddr;
}

struct headers {
    ethernet_t eth;
    ipv4_t ip;
}

struct metadata_t {
    bit<32> flow_id;
    bit<32> hash_idx;

    bit<32> carry_key;
    bit<32> carry_val;

    bit<1>  done;
    bit<32> evict_thresh;
    
    bit<32> collisions; // Tracks collisions inside the pipeline pass
}

/* ================= PARSER ================= */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.eth);
        transition select(hdr.eth.ethType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ip);
        transition accept;
    }
}

/* ================= INGRESS ================= */

control MyIngress(inout headers hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    /* -------- HashPipe Data Tables -------- */
    register<bit<32>>(MAX_TABLE_SIZE) key_0;
    register<bit<32>>(MAX_TABLE_SIZE) val_0;

    register<bit<32>>(MAX_TABLE_SIZE) key_1;
    register<bit<32>>(MAX_TABLE_SIZE) val_1;

    register<bit<32>>(MAX_TABLE_SIZE) key_2;
    register<bit<32>>(MAX_TABLE_SIZE) val_2;

    register<bit<32>>(MAX_TABLE_SIZE) key_3;
    register<bit<32>>(MAX_TABLE_SIZE) val_3;

    /* -------- Adaptive Control Registers -------- */
    register<bit<32>>(1) seed_reg_0;
    register<bit<32>>(1) seed_reg_1;
    register<bit<32>>(1) seed_reg_2;
    register<bit<32>>(1) seed_reg_3;

    register<bit<32>>(1) stage_enable_reg; 
    register<bit<32>>(1) evict_thresh_reg; 

    /* -------- Telemetry Counters -------- */
    register<bit<32>>(1) packet_counter;
    register<bit<32>>(1) collision_counter;
    register<bit<32>>(1) eviction_counter;

    /* -------- Stage Logic -------- */
    action process_stage_0() {
        bit<32> k;
        bit<32> v;

        key_0.read(k, meta.hash_idx);
        val_0.read(v, meta.hash_idx);

        if (k == meta.carry_key) {
            v = v + meta.carry_val;
            val_0.write(meta.hash_idx, v);
            meta.done = 1;
        }
        else if (k == 0) {
            key_0.write(meta.hash_idx, meta.carry_key);
            val_0.write(meta.hash_idx, meta.carry_val);
            meta.done = 1;
        }
        else {
            meta.collisions = meta.collisions + 1; // COLLISION DETECTED
            bit<32> temp_k = k;
            bit<32> temp_v = v;

            key_0.write(meta.hash_idx, meta.carry_key);
            val_0.write(meta.hash_idx, meta.carry_val);

            meta.carry_key = temp_k;
            meta.carry_val = temp_v;
        }
    }

    action process_stage_1() {
        bit<32> k;
        bit<32> v;

        key_1.read(k, meta.hash_idx);
        val_1.read(v, meta.hash_idx);

        if (meta.done == 0) {
            if (k == meta.carry_key) {
                v = v + meta.carry_val;
                val_1.write(meta.hash_idx, v);
                meta.done = 1;
            }
            else if (k == 0) {
                key_1.write(meta.hash_idx, meta.carry_key);
                val_1.write(meta.hash_idx, meta.carry_val);
                meta.done = 1;
            }
            else {
                meta.collisions = meta.collisions + 1; // COLLISION DETECTED
                if (v + meta.evict_thresh < meta.carry_val) {
                    bit<32> temp_k = k;
                    bit<32> temp_v = v;

                    key_1.write(meta.hash_idx, meta.carry_key);
                    val_1.write(meta.hash_idx, meta.carry_val);

                    meta.carry_key = temp_k;
                    meta.carry_val = temp_v;
                }
            }
        }
    }

    action process_stage_2() {
        bit<32> k;
        bit<32> v;

        key_2.read(k, meta.hash_idx);
        val_2.read(v, meta.hash_idx);

        if (meta.done == 0) {
            if (k == meta.carry_key) {
                v = v + meta.carry_val;
                val_2.write(meta.hash_idx, v);
                meta.done = 1;
            }
            else if (k == 0) {
                key_2.write(meta.hash_idx, meta.carry_key);
                val_2.write(meta.hash_idx, meta.carry_val);
                meta.done = 1;
            }
            else {
                meta.collisions = meta.collisions + 1; // COLLISION DETECTED
                if (v + meta.evict_thresh < meta.carry_val) {
                    bit<32> temp_k = k;
                    bit<32> temp_v = v;

                    key_2.write(meta.hash_idx, meta.carry_key);
                    val_2.write(meta.hash_idx, meta.carry_val);

                    meta.carry_key = temp_k;
                    meta.carry_val = temp_v;
                }
            }
        }
    }

    action process_stage_3() {
        bit<32> k;
        bit<32> v;

        key_3.read(k, meta.hash_idx);
        val_3.read(v, meta.hash_idx);

        if (meta.done == 0) {
            if (k == meta.carry_key) {
                v = v + meta.carry_val;
                val_3.write(meta.hash_idx, v);
            }
            else if (k == 0) {
                key_3.write(meta.hash_idx, meta.carry_key);
                val_3.write(meta.hash_idx, meta.carry_val);
            }
            else {
                meta.collisions = meta.collisions + 1; // COLLISION DETECTED
                if (v + meta.evict_thresh < meta.carry_val) {
                    key_3.write(meta.hash_idx, meta.carry_key);
                    val_3.write(meta.hash_idx, meta.carry_val);
                }
            }
        }
    }

    apply {
        if (hdr.ip.isValid()) {
            
            /* --- Count Total Packets --- */
            bit<32> pkt_cnt;
            packet_counter.read(pkt_cnt, 0);
            pkt_cnt = pkt_cnt + 1;
            packet_counter.write(0, pkt_cnt);

            /* Fetch Control Plane Configurations */
            bit<32> active_stages;
            stage_enable_reg.read(active_stages, 0);
            evict_thresh_reg.read(meta.evict_thresh, 0);

            bit<32> seed0; seed_reg_0.read(seed0, 0);

            bit<32> seed1; seed_reg_1.read(seed1, 0);

            bit<32> seed2; seed_reg_2.read(seed2, 0);

            bit<32> seed3; seed_reg_3.read(seed3, 0);
           

            /* Initialize Flow Tracking */
            hash(meta.flow_id, HashAlgorithm.crc32, 32w0,
                 {hdr.ip.srcAddr, hdr.ip.dstAddr, hdr.ip.protocol},
                  32w0xffffffff);

            meta.carry_key = meta.flow_id;
            meta.carry_val = 1;
            meta.done = 0;
            meta.collisions = 0; // Initialize collision counter

            /* --- Pipeline Stages --- */
            if ((active_stages & 1) == 1) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, seed0}, 32w0xffffffff);
                meta.hash_idx = meta.hash_idx & 3;
                process_stage_0();
            }

            if (meta.done == 0 && (active_stages & 2) == 2) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, seed1}, 32w0xffffffff);
                meta.hash_idx = meta.hash_idx & 3;
                process_stage_1();
            }

            if (meta.done == 0 && (active_stages & 4) == 4) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, seed2}, 32w0xffffffff);
                meta.hash_idx = meta.hash_idx & 3;
                process_stage_2();
            }

            if (meta.done == 0 && (active_stages & 8) == 8) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, seed3}, 32w0xffffffff);
                meta.hash_idx = meta.hash_idx & 3;
                process_stage_3();
            }

            /* --- Aggregate Metrics to Registers --- */
            if (meta.collisions > 0) {
                bit<32> coll_cnt;
                collision_counter.read(coll_cnt, 0);
                coll_cnt = coll_cnt + meta.collisions;
                collision_counter.write(0, coll_cnt);
            }

            if (meta.done == 0) {
                bit<32> ev_cnt;
                eviction_counter.read(ev_cnt, 0);
                ev_cnt = ev_cnt + 1;
                eviction_counter.write(0, ev_cnt);
            }

            /* Forward packet */
            standard_metadata.egress_spec = 1;
        }
    }
}

/* ================= EGRESS ================= */
control MyEgress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {}
}
control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata_t meta) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
    }
}
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
