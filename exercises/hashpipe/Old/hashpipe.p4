#include <core.p4>
#include <v1model.p4>

/* ================= CONFIG ================= */
#define D 4                 // number of pipeline stages
#define TABLE_SIZE 32w2    // per-stage table size

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

    /* -------- Registers (HashPipe tables) -------- */
    register<bit<32>>(TABLE_SIZE) key_0;
    register<bit<32>>(TABLE_SIZE) val_0;

    register<bit<32>>(TABLE_SIZE) key_1;
    register<bit<32>>(TABLE_SIZE) val_1;

    register<bit<32>>(TABLE_SIZE) key_2;
    register<bit<32>>(TABLE_SIZE) val_2;

    register<bit<32>>(TABLE_SIZE) key_3;
    register<bit<32>>(TABLE_SIZE) val_3;

    /* -------- Stage Logic Template -------- */
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
                if (v < meta.carry_val) {
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
                if (v < meta.carry_val) {
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
                if (v < meta.carry_val) {
                    key_3.write(meta.hash_idx, meta.carry_key);
                    val_3.write(meta.hash_idx, meta.carry_val);
                }
            }
        }
    }

    apply {
        if (hdr.ip.isValid()) {
        
            /*meta.flow_id = (bit<32>)hdr.ip.srcAddr ^ (bit<32>)hdr.ip.dstAddr ^ (bit<32>)hdr.ip.protocol;*/
            hash(meta.flow_id, HashAlgorithm.crc32, 32w0,
                 {hdr.ip.srcAddr, hdr.ip.dstAddr, hdr.ip.protocol},
                  32w0xffffffff);

            meta.carry_key = meta.flow_id;
            meta.carry_val = 1;
            meta.done = 0;

            /* Stage 0 (Seed 1) */
            hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, 32w1}, TABLE_SIZE);
            process_stage_0();

            /* Stage 1 (Seed 2) */
            if (meta.done == 0) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, 32w2}, TABLE_SIZE);
                process_stage_1();
            }

            /* Stage 2 (Seed 3) */
            if (meta.done == 0) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, 32w3}, TABLE_SIZE);
                process_stage_2();
            }

            /* Stage 3 (Seed 4) */
            if (meta.done == 0) {
                hash(meta.hash_idx, HashAlgorithm.crc32, 32w0, {meta.carry_key, 32w4}, TABLE_SIZE);
                process_stage_3();
            }

            /* Forward packet */
            standard_metadata.egress_spec = 1;
        }
    }
}

/* ================= EGRESS ================= */

control MyEgress(inout headers hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/* ================= CHECKSUM ================= */
control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}

/* ================= DEPARSER ================= */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
    }
}

/* ================= SWITCH ================= */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

