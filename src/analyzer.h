#ifndef PCAPREPORT_ANALYZER_H
#define PCAPREPORT_ANALYZER_H

#include <stddef.h>
#include <stdint.h>
#include "decode.h"

/* ------------------------------------------------------------ time series */

enum {
    TS_BYTES_TCP, TS_BYTES_UDP, TS_BYTES_OTHER,
    TS_PKTS_TCP, TS_PKTS_UDP, TS_PKTS_OTHER,
    TS_SYN, TS_RST, TS_RETRANS,
    TS_NCHAN
};

#define TS_MAX_BUCKETS 600

/* Adaptive-resolution histogram over time: bounded memory regardless of
 * capture length. Bucket width climbs the ladder 1,2,10,20,100,200 ms ... so
 * that the full time span always fits in TS_MAX_BUCKETS buckets. */
typedef struct {
    int64_t t0;          /* start of bucket 0 (ns, multiple of width) */
    int64_t width;       /* bucket width (ns)                         */
    size_t n;            /* buckets in use                            */
    double v[TS_MAX_BUCKETS][TS_NCHAN];
} timeseries_t;

/* ------------------------------------------------------------------ flows */

enum { TCPS_NONE = 0, TCPS_SYN, TCPS_SYNACK, TCPS_ESTABLISHED };

/* Bidirectional flow keyed by canonical 5-tuple. Index 0 = a->b, 1 = b->a. */
typedef struct flow {
    struct flow *hnext;
    ip_addr_t a, b;
    uint16_t pa, pb;
    uint8_t proto;
    uint8_t init_dir;       /* direction index of the initiator (client) */
    uint8_t init_by_syn;    /* initiator determined from a SYN           */
    uint8_t tcp_state;
    uint8_t flags_seen[2];
    uint8_t seq_valid[2];
    uint8_t rst_dir_mask;   /* bit d set: RST sent in direction d        */
    uint8_t fin_dir_mask;
    uint32_t hash;
    uint64_t pkts[2];
    uint64_t bytes[2];      /* IP-level bytes                           */
    uint64_t payload[2];
    int64_t first_ns, last_ns;
    int64_t syn_ns, synack_ns;
    int64_t rtt_ns;         /* SYN -> handshake ACK, -1 if unknown       */
    uint32_t next_seq[2];
    uint32_t syn_count[2];
    uint32_t data_segs[2];
    uint32_t retrans[2];
    uint32_t seq_gaps[2];
    uint32_t zero_win[2];
    uint32_t bad_flags;
} flow_t;

typedef struct flow_chunk {
    struct flow_chunk *next;
    size_t used;
    flow_t items[4096];
} flow_chunk_t;

typedef struct {
    flow_t **buckets;
    size_t nbuckets;
    size_t count;
    size_t limit;
    uint64_t dropped_pkts;  /* packets of flows not tracked due to limit */
    flow_chunk_t *chunks;
} flow_table_t;

/* ------------------------------------------------------------------ hosts */

typedef struct host {
    struct host *hnext;
    ip_addr_t ip;
    uint32_t hash;
    uint64_t pkts_sent, pkts_recv;
    uint64_t bytes_sent, bytes_recv;
    uint64_t udp_pkts_recv, udp_pkts_sent;
    uint64_t rst_sent;
    uint64_t syn_sent;
    uint64_t bad_flags_sent;
    uint64_t bad_csum_sent;
    int64_t first_ns, last_ns;
} host_t;

typedef struct host_chunk {
    struct host_chunk *next;
    size_t used;
    host_t items[4096];
} host_chunk_t;

typedef struct {
    host_t **buckets;
    size_t nbuckets;
    size_t count;
    size_t limit;
    uint64_t dropped;
    host_chunk_t *chunks;
} host_table_t;

/* -------------------------------------------------------------- per file */

typedef struct {
    char *path;
    int ok;                  /* opened and parsed (possibly partially) */
    char status[160];        /* "ok", "truncated", error text          */
    const char *format;
    uint32_t linktype;       /* first seen linktype                    */
    int mixed_linktypes;
    uint64_t packets;
    uint64_t bytes;
    int64_t first_ns, last_ns;
    uint64_t ts_backwards;   /* timestamps going back in time          */
} file_stats_t;

/* ------------------------------------------------------------- histograms */

#define SIZE_BINS 7
extern const char *const size_bin_labels[SIZE_BINS];

enum { PROTO_IDX_TCP, PROTO_IDX_UDP, PROTO_IDX_ICMP, PROTO_IDX_OTHER, PROTO_IDX_N };

/* ------------------------------------------------------------- analyzer */

typedef struct {
    int verify_checksums;
    size_t max_flows;
    size_t max_hosts;
} analyzer_opts_t;

typedef struct {
    analyzer_opts_t opts;

    /* global counters */
    uint64_t packets, bytes;           /* all frames, wire length       */
    uint64_t captured_bytes;
    uint64_t ipv4_pkts, ipv6_pkts;
    uint64_t non_ip_pkts;
    uint64_t unsupported_link_pkts;
    uint64_t malformed_pkts;
    uint64_t snap_truncated_pkts;      /* frames cut by snaplen          */
    uint64_t snap_unparsed_pkts;       /* ... and L4 unusable because of it */
    uint64_t fragments;
    uint64_t perr_counts[16];          /* per PERR_* bit                 */
    uint64_t ip_csum_checked, ip_csum_bad;
    uint64_t l4_csum_checked, l4_csum_bad;
    uint64_t proto_pkts[PROTO_IDX_N], proto_bytes[PROTO_IDX_N];
    uint64_t size_hist[PROTO_IDX_N][SIZE_BINS];
    int64_t first_ns, last_ns;
    int have_time;
    int64_t ts_upper_bound;            /* later timestamps are implausible */

    /* TCP */
    uint64_t tcp_flag_counts[8];       /* by bit                         */
    uint64_t tcp_synack, tcp_pure_ack;
    uint64_t tcp_data_segs, tcp_retrans, tcp_seq_gaps, tcp_zero_win;
    uint64_t tcp_syn_fin, tcp_syn_rst, tcp_null, tcp_xmas, tcp_fin_noack;
    /* misc anomalies */
    uint64_t land_pkts, port0_pkts, mcast_src_pkts;
    uint64_t ts_backwards;
    uint64_t ts_implausible;           /* before 1995 or > 1 day in future */
    uint64_t unsupported_linktypes[8]; /* distinct values seen (first 8)  */
    size_t n_unsupported_linktypes;

    timeseries_t *ts;
    flow_table_t flows;
    host_table_t hosts;

    file_stats_t *files;
    size_t nfiles;
} analyzer_t;

void analyzer_init(analyzer_t *an, const analyzer_opts_t *opts);
void analyzer_free(analyzer_t *an);

/* Processes one file; returns 0 if it could be read (even partially), -1 if not. */
int analyzer_process_file(analyzer_t *an, const char *path);

/* Feeds a single decoded packet (exposed for tests). */
void analyzer_packet(analyzer_t *an, const pcap_packet_t *pkt);

/* Flow helpers. */
const ip_addr_t *flow_client(const flow_t *f);
const ip_addr_t *flow_server(const flow_t *f);
uint16_t flow_client_port(const flow_t *f);
uint16_t flow_server_port(const flow_t *f);
uint64_t flow_total_bytes(const flow_t *f);
uint64_t flow_total_pkts(const flow_t *f);
/* Array of pointers to all flows (caller frees the array, not the flows). */
flow_t **analyzer_flow_list(const analyzer_t *an, size_t *n);
host_t **analyzer_host_list(const analyzer_t *an, size_t *n);

#endif
