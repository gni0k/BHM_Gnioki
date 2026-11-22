#define _POSIX_C_SOURCE 200809L
#include "analyzer.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *const size_bin_labels[SIZE_BINS] = {
    "<=64", "65-127", "128-255", "256-511", "512-1023", "1024-1517", ">=1518"
};

static int size_bin(uint32_t len)
{
    if (len <= 64) return 0;
    if (len < 128) return 1;
    if (len < 256) return 2;
    if (len < 512) return 3;
    if (len < 1024) return 4;
    if (len < 1518) return 5;
    return 6;
}

static int proto_index(uint8_t proto)
{
    switch (proto) {
    case PROTO_TCP: return PROTO_IDX_TCP;
    case PROTO_UDP: return PROTO_IDX_UDP;
    case PROTO_ICMP:
    case PROTO_ICMPV6: return PROTO_IDX_ICMP;
    default: return PROTO_IDX_OTHER;
    }
}

/* ------------------------------------------------------------ time series */

static int64_t floor_div(int64_t a, int64_t b)
{
    int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0))) q--;
    return q;
}

/* Width ladder: 1ms * {1,2,10,20,100,200,...}. */
static int64_t ts_next_width(int64_t w)
{
    int64_t ms = w / 1000000LL;
    int64_t p = 1;
    while (p * 10 <= ms) p *= 10;
    int64_t next = (ms == p) ? 2 * p : 10 * p;
    if (next > INT64_MAX / 2000000LL) return w; /* saturate (~ 146 years per bucket) */
    return next * 1000000LL;
}

static void ts_remap(timeseries_t *ts, int64_t lo, int64_t hi)
{
    int64_t w = ts->width;
    for (;;) {
        int64_t a = floor_div(lo, w), b = floor_div(hi, w);
        if (b - a + 1 <= (int64_t)TS_MAX_BUCKETS) break;
        int64_t nw = ts_next_width(w);
        if (nw == w) break;
        w = nw;
    }
    int64_t new_t0 = floor_div(lo, w) * w;
    double (*tmp)[TS_NCHAN] = xcalloc(TS_MAX_BUCKETS, sizeof *tmp);
    size_t new_n = 0;
    for (size_t i = 0; i < ts->n; i++) {
        int64_t start = ts->t0 + (int64_t)i * ts->width;
        int64_t j = floor_div(start - new_t0, w);
        if (j < 0 || j >= TS_MAX_BUCKETS) continue; /* cannot happen; defensive */
        for (int c = 0; c < TS_NCHAN; c++) tmp[j][c] += ts->v[i][c];
        if ((size_t)j + 1 > new_n) new_n = (size_t)j + 1;
    }
    int64_t span = floor_div(hi - new_t0, w) + 1;
    if (span > TS_MAX_BUCKETS) span = TS_MAX_BUCKETS;
    if ((size_t)span > new_n) new_n = (size_t)span;
    memcpy(ts->v, tmp, TS_MAX_BUCKETS * sizeof *tmp);
    free(tmp);
    ts->t0 = new_t0;
    ts->width = w;
    ts->n = new_n;
}

static void ts_add(timeseries_t *ts, int64_t t, int chan, double v)
{
    if (ts->n == 0) {
        ts->width = 1000000LL;
        ts->t0 = floor_div(t, ts->width) * ts->width;
        ts->n = 1;
        memset(ts->v[0], 0, sizeof ts->v[0]);
    }
    int64_t idx = floor_div(t - ts->t0, ts->width);
    if (idx < 0 || idx >= TS_MAX_BUCKETS) {
        int64_t end = ts->t0 + (int64_t)ts->n * ts->width - 1;
        ts_remap(ts, MIN(ts->t0, t), MAX(end, t));
        idx = floor_div(t - ts->t0, ts->width);
        if (idx < 0 || idx >= TS_MAX_BUCKETS) return;
    }
    if ((size_t)idx >= ts->n) {
        for (size_t i = ts->n; i <= (size_t)idx; i++) memset(ts->v[i], 0, sizeof ts->v[i]);
        ts->n = (size_t)idx + 1;
    }
    ts->v[idx][chan] += v;
}

/* ------------------------------------------------------------------ hashing */

static uint32_t hash_bytes(uint32_t h, const void *p, size_t n)
{
    const unsigned char *c = p;
    for (size_t i = 0; i < n; i++) { h ^= c[i]; h *= 16777619u; }
    return h;
}

/* ------------------------------------------------------------------ flows */

static void flows_init(flow_table_t *t, size_t limit)
{
    memset(t, 0, sizeof *t);
    t->nbuckets = 1u << 14;
    t->buckets = xcalloc(t->nbuckets, sizeof *t->buckets);
    t->limit = limit;
}

static void flows_free(flow_table_t *t)
{
    flow_chunk_t *c = t->chunks;
    while (c) { flow_chunk_t *n = c->next; free(c); c = n; }
    free(t->buckets);
    memset(t, 0, sizeof *t);
}

static void flows_grow(flow_table_t *t)
{
    size_t nb = t->nbuckets * 2;
    flow_t **b = xcalloc(nb, sizeof *b);
    for (size_t i = 0; i < t->nbuckets; i++) {
        flow_t *f = t->buckets[i];
        while (f) {
            flow_t *n = f->hnext;
            size_t j = f->hash & (nb - 1);
            f->hnext = b[j];
            b[j] = f;
            f = n;
        }
    }
    free(t->buckets);
    t->buckets = b;
    t->nbuckets = nb;
}

static flow_t *flow_alloc(flow_table_t *t)
{
    if (!t->chunks || t->chunks->used == ARRAY_LEN(t->chunks->items)) {
        flow_chunk_t *c = xmalloc(sizeof *c);
        c->used = 0;
        c->next = t->chunks;
        t->chunks = c;
    }
    flow_t *f = &t->chunks->items[t->chunks->used++];
    memset(f, 0, sizeof *f);
    return f;
}

/* Returns flow and direction (0: a->b). NULL if table full. */
static flow_t *flow_lookup(flow_table_t *t, const pkt_info_t *pi, int *dir, int *created)
{
    const ip_addr_t *a = &pi->src, *b = &pi->dst;
    uint16_t pa = pi->sport, pb = pi->dport;
    int c = ip_cmp(a, b);
    *dir = 0;
    if (c > 0 || (c == 0 && pa > pb)) {
        const ip_addr_t *x = a; a = b; b = x;
        uint16_t y = pa; pa = pb; pb = y;
        *dir = 1;
    }
    uint32_t h = 2166136261u;
    h = hash_bytes(h, a->a, 16);
    h = hash_bytes(h, b->a, 16);
    h = hash_bytes(h, &pa, 2);
    h = hash_bytes(h, &pb, 2);
    h = hash_bytes(h, &pi->proto, 1);
    *created = 0;
    for (flow_t *f = t->buckets[h & (t->nbuckets - 1)]; f; f = f->hnext) {
        if (f->hash == h && f->proto == pi->proto && f->pa == pa && f->pb == pb &&
            ip_cmp(&f->a, a) == 0 && ip_cmp(&f->b, b) == 0)
            return f;
    }
    if (t->count >= t->limit) return NULL;
    if (t->count >= t->nbuckets) flows_grow(t);
    flow_t *f = flow_alloc(t);
    f->a = *a;
    f->b = *b;
    f->pa = pa;
    f->pb = pb;
    f->proto = pi->proto;
    f->hash = h;
    f->init_dir = (uint8_t)*dir;
    f->rtt_ns = -1;
    f->first_ns = pi->ts_ns;
    f->last_ns = pi->ts_ns;
    size_t j = h & (t->nbuckets - 1);
    f->hnext = t->buckets[j];
    t->buckets[j] = f;
    t->count++;
    *created = 1;
    return f;
}

const ip_addr_t *flow_client(const flow_t *f) { return f->init_dir == 0 ? &f->a : &f->b; }
const ip_addr_t *flow_server(const flow_t *f) { return f->init_dir == 0 ? &f->b : &f->a; }
uint16_t flow_client_port(const flow_t *f) { return f->init_dir == 0 ? f->pa : f->pb; }
uint16_t flow_server_port(const flow_t *f) { return f->init_dir == 0 ? f->pb : f->pa; }
uint64_t flow_total_bytes(const flow_t *f) { return f->bytes[0] + f->bytes[1]; }
uint64_t flow_total_pkts(const flow_t *f) { return f->pkts[0] + f->pkts[1]; }

/* When no SYN was seen, guess the server side: well-known/registered port vs ephemeral. */
static void flow_guess_direction(flow_t *f)
{
    if (f->init_by_syn) return;
    uint16_t p0 = f->pa, p1 = f->pb; /* a's port, b's port */
    int a_server;
    int a_eph = p0 >= 49152, b_eph = p1 >= 49152;
    if (a_eph != b_eph) a_server = b_eph;
    else if (p0 < 1024 || p1 < 1024) a_server = p0 < p1;
    else return; /* keep first-packet direction */
    f->init_dir = a_server ? 1 : 0;
}

static void tcp_update(analyzer_t *an, flow_t *f, int d, const pkt_info_t *pi)
{
    uint8_t fl = pi->tcp_flags;
    int syn = fl & TCP_SYN, ack = fl & TCP_ACK, fin = fl & TCP_FIN, rst = fl & TCP_RST;
    f->flags_seen[d] |= fl;

    if (syn && !ack) {
        f->syn_count[d]++;
        if (f->tcp_state == TCPS_NONE || (f->tcp_state == TCPS_SYN && d == f->init_dir)) {
            f->syn_ns = pi->ts_ns; /* latest SYN: RTT excludes retransmission timeouts */
            f->tcp_state = TCPS_SYN;
            f->init_dir = (uint8_t)d;
            f->init_by_syn = 1;
        }
    } else if (syn && ack) {
        an->tcp_synack++;
        if (f->tcp_state == TCPS_SYN && d != f->init_dir) {
            f->tcp_state = TCPS_SYNACK;
            f->synack_ns = pi->ts_ns;
        }
    } else if (ack && f->tcp_state == TCPS_SYNACK && d == f->init_dir) {
        f->tcp_state = TCPS_ESTABLISHED;
        f->rtt_ns = pi->ts_ns - f->syn_ns;
    }
    if (rst) f->rst_dir_mask |= (uint8_t)(1u << d);
    if (fin) f->fin_dir_mask |= (uint8_t)(1u << d);

    int bad = 0;
    if (syn && fin) { an->tcp_syn_fin++; bad = 1; }
    if (syn && rst) { an->tcp_syn_rst++; bad = 1; }
    if (fl == 0) { an->tcp_null++; bad = 1; }
    if ((fl & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) { an->tcp_xmas++; bad = 1; }
    else if (fin && !ack && !syn && !rst) { an->tcp_fin_noack++; bad = 1; }
    if (bad) f->bad_flags++;

    if (pi->window == 0 && !rst && !syn) { f->zero_win[d]++; an->tcp_zero_win++; }

    uint32_t seglen = pi->payload_len + (syn ? 1u : 0u) + (fin ? 1u : 0u);
    if (syn) {
        f->next_seq[d] = pi->seq + seglen;
        f->seq_valid[d] = 1;
    } else if (seglen > 0 && !rst) {
        if (!f->seq_valid[d]) {
            f->next_seq[d] = pi->seq + seglen;
            f->seq_valid[d] = 1;
        } else {
            int32_t diff = (int32_t)(pi->seq - f->next_seq[d]);
            uint32_t end = pi->seq + seglen;
            if (diff < 0) {
                int keepalive = pi->payload_len <= 1 && !fin && pi->seq == f->next_seq[d] - 1;
                if (!keepalive) {
                    f->retrans[d]++;
                    an->tcp_retrans++;
                    ts_add(an->ts, pi->ts_ns, TS_RETRANS, 1);
                }
            } else if (diff > 0) {
                f->seq_gaps[d]++;
                an->tcp_seq_gaps++;
            }
            if ((int32_t)(end - f->next_seq[d]) > 0) f->next_seq[d] = end;
        }
    }
    if (pi->payload_len > 0) { f->data_segs[d]++; an->tcp_data_segs++; }
}

/* ------------------------------------------------------------------ hosts */

static void hosts_init(host_table_t *t, size_t limit)
{
    memset(t, 0, sizeof *t);
    t->nbuckets = 1u << 12;
    t->buckets = xcalloc(t->nbuckets, sizeof *t->buckets);
    t->limit = limit;
}

static void hosts_free(host_table_t *t)
{
    host_chunk_t *c = t->chunks;
    while (c) { host_chunk_t *n = c->next; free(c); c = n; }
    free(t->buckets);
    memset(t, 0, sizeof *t);
}

static host_t *host_get(host_table_t *t, const ip_addr_t *ip, int64_t ts)
{
    uint32_t h = hash_bytes(2166136261u, ip->a, 16);
    for (host_t *x = t->buckets[h & (t->nbuckets - 1)]; x; x = x->hnext)
        if (x->hash == h && ip_cmp(&x->ip, ip) == 0) {
            if (ts < x->first_ns) x->first_ns = ts;
            if (ts > x->last_ns) x->last_ns = ts;
            return x;
        }
    if (t->count >= t->limit) { t->dropped++; return NULL; }
    if (t->count >= t->nbuckets) {
        size_t nb = t->nbuckets * 2;
        host_t **b = xcalloc(nb, sizeof *b);
        for (size_t i = 0; i < t->nbuckets; i++) {
            host_t *x = t->buckets[i];
            while (x) {
                host_t *n = x->hnext;
                size_t j = x->hash & (nb - 1);
                x->hnext = b[j];
                b[j] = x;
                x = n;
            }
        }
        free(t->buckets);
        t->buckets = b;
        t->nbuckets = nb;
    }
    if (!t->chunks || t->chunks->used == ARRAY_LEN(t->chunks->items)) {
        host_chunk_t *c = xmalloc(sizeof *c);
        c->used = 0;
        c->next = t->chunks;
        t->chunks = c;
    }
    host_t *x = &t->chunks->items[t->chunks->used++];
    memset(x, 0, sizeof *x);
    x->ip = *ip;
    x->hash = h;
    x->first_ns = x->last_ns = ts;
    size_t j = h & (t->nbuckets - 1);
    x->hnext = t->buckets[j];
    t->buckets[j] = x;
    t->count++;
    return x;
}

/* --------------------------------------------------------------- analyzer */

static int64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

void analyzer_init(analyzer_t *an, const analyzer_opts_t *opts)
{
    memset(an, 0, sizeof *an);
    an->opts = *opts;
    an->ts = xcalloc(1, sizeof *an->ts);
    an->ts_upper_bound = now_ns() + 86400LL * 1000000000LL; /* tolerate 1 day clock skew */
    flows_init(&an->flows, opts->max_flows);
    hosts_init(&an->hosts, opts->max_hosts);
}

void analyzer_free(analyzer_t *an)
{
    flows_free(&an->flows);
    hosts_free(&an->hosts);
    free(an->ts);
    for (size_t i = 0; i < an->nfiles; i++) free(an->files[i].path);
    free(an->files);
    memset(an, 0, sizeof *an);
}

static void note_unsupported_link(analyzer_t *an, uint32_t lt)
{
    for (size_t i = 0; i < an->n_unsupported_linktypes; i++)
        if (an->unsupported_linktypes[i] == lt) return;
    if (an->n_unsupported_linktypes < ARRAY_LEN(an->unsupported_linktypes))
        an->unsupported_linktypes[an->n_unsupported_linktypes++] = lt;
}

void analyzer_packet(analyzer_t *an, const pcap_packet_t *pkt)
{
    pkt_info_t pi;
    decode_status_t st = decode_packet(pkt, an->opts.verify_checksums, &pi);

    an->packets++;
    an->bytes += pkt->origlen;
    an->captured_bytes += pkt->caplen;
    if (pi.snap_truncated) an->snap_truncated_pkts++;

    /* Time bookkeeping: implausible timestamps are excluded from the timeline. */
    int64_t t = pkt->ts_ns;
    int time_ok = t >= 788918400LL * 1000000000LL && t <= an->ts_upper_bound;
    if (!time_ok) an->ts_implausible++;
    if (time_ok) {
        if (!an->have_time) { an->first_ns = an->last_ns = t; an->have_time = 1; }
        if (t < an->first_ns) an->first_ns = t;
        if (t > an->last_ns) an->last_ns = t;
    }

    if (st == DEC_UNSUPPORTED_LINK) {
        an->unsupported_link_pkts++;
        note_unsupported_link(an, pkt->linktype);
        return;
    }
    if (st == DEC_NON_IP) {
        an->non_ip_pkts++;
        an->proto_pkts[PROTO_IDX_OTHER]++;
        an->proto_bytes[PROTO_IDX_OTHER] += pkt->origlen;
        if (time_ok) {
            ts_add(an->ts, t, TS_BYTES_OTHER, pkt->origlen);
            ts_add(an->ts, t, TS_PKTS_OTHER, 1);
        }
        return;
    }
    for (int b = 0; b < 16; b++)
        if (pi.err & (1u << b)) an->perr_counts[b]++;
    if (pi.ip_csum_ok >= 0) { an->ip_csum_checked++; if (!pi.ip_csum_ok) an->ip_csum_bad++; }
    if (pi.l4_csum_ok >= 0) { an->l4_csum_checked++; if (!pi.l4_csum_ok) an->l4_csum_bad++; }

    if (st == DEC_MALFORMED) {
        const unsigned trunc_bits = PERR_TRUNC_L2 | PERR_TRUNC_L3 | PERR_TRUNC_L4;
        /* Cut by snaplen only: not a protocol violation, just not analysable. */
        if (pi.snap_truncated && (pi.err & ~trunc_bits & ~(PERR_BAD_IPCSUM | PERR_BAD_L4CSUM)) == 0)
            an->snap_unparsed_pkts++;
        else
            an->malformed_pkts++;
        if (pi.ipver == 0) return;
    }

    if (pi.ipver == 4) an->ipv4_pkts++;
    else if (pi.ipver == 6) an->ipv6_pkts++;
    if (pi.is_fragment) an->fragments++;

    int pidx = proto_index(pi.proto);
    an->proto_pkts[pidx]++;
    an->proto_bytes[pidx] += pkt->origlen;
    an->size_hist[pidx][size_bin(pkt->origlen)]++;
    if (time_ok) {
        int bc = pidx == PROTO_IDX_TCP ? TS_BYTES_TCP : pidx == PROTO_IDX_UDP ? TS_BYTES_UDP : TS_BYTES_OTHER;
        ts_add(an->ts, t, bc, pkt->origlen);
        ts_add(an->ts, t, bc + 3, 1); /* matching packet channel */
    }

    if (ip_cmp(&pi.src, &pi.dst) == 0 && pi.has_l4 && pi.sport == pi.dport) an->land_pkts++;
    if (ip_is_multicast_or_broadcast(&pi.src)) an->mcast_src_pkts++;

    host_t *hs = host_get(&an->hosts, &pi.src, t);
    host_t *hd = host_get(&an->hosts, &pi.dst, t);
    uint32_t iplen = pi.ip_len ? pi.ip_len : pkt->origlen;
    if (hs) { hs->pkts_sent++; hs->bytes_sent += iplen; if (pi.err & (PERR_BAD_IPCSUM | PERR_BAD_L4CSUM)) hs->bad_csum_sent++; }
    if (hd) { hd->pkts_recv++; hd->bytes_recv += iplen; }
    if (pi.proto == PROTO_UDP) {
        if (hs) hs->udp_pkts_sent++;
        if (hd) hd->udp_pkts_recv++;
    }

    if (!pi.has_l4) return;
    if (pi.sport == 0 || pi.dport == 0) an->port0_pkts++;

    if (pi.proto == PROTO_TCP) {
        for (int b = 0; b < 8; b++)
            if (pi.tcp_flags & (1u << b)) an->tcp_flag_counts[b]++;
        if (pi.tcp_flags == TCP_ACK && pi.payload_len == 0) an->tcp_pure_ack++;
        if (time_ok && (pi.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) ts_add(an->ts, t, TS_SYN, 1);
        if (time_ok && (pi.tcp_flags & TCP_RST)) ts_add(an->ts, t, TS_RST, 1);
        if (hs && (pi.tcp_flags & TCP_RST)) hs->rst_sent++;
        if (hs && (pi.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) hs->syn_sent++;
    }

    int dir, created;
    flow_t *f = flow_lookup(&an->flows, &pi, &dir, &created);
    if (!f) { an->flows.dropped_pkts++; return; }
    f->pkts[dir]++;
    f->bytes[dir] += iplen;
    f->payload[dir] += pi.payload_len;
    if (t < f->first_ns) f->first_ns = t;
    if (t > f->last_ns) f->last_ns = t;
    if (pi.proto == PROTO_TCP) {
        uint64_t before = f->bad_flags;
        tcp_update(an, f, dir, &pi);
        if (hs && f->bad_flags != before) hs->bad_flags_sent++;
    }
    (void)created;
}

int analyzer_process_file(analyzer_t *an, const char *path)
{
    an->files = xreallocarray(an->files, an->nfiles + 1, sizeof *an->files);
    file_stats_t *fs = &an->files[an->nfiles++];
    memset(fs, 0, sizeof *fs);
    fs->path = xstrdup(path);

    char err[256] = "";
    pcap_reader_t *r = pcap_reader_open(path, err, sizeof err);
    if (!r) {
        snprintf(fs->status, sizeof fs->status, "not processed: %.140s", err);
        log_error("%s: %s", path, err);
        return -1;
    }
    fs->ok = 1;
    fs->format = pcap_reader_format(r) == PCAP_FMT_NG ? "pcapng" : "pcap";
    int64_t prev = 0;
    int have_prev = 0;
    pcap_packet_t pkt;
    int rc;
    while ((rc = pcap_reader_next(r, &pkt)) == 1) {
        if (fs->packets == 0) { fs->linktype = pkt.linktype; fs->first_ns = fs->last_ns = pkt.ts_ns; }
        else if (pkt.linktype != fs->linktype) fs->mixed_linktypes = 1;
        fs->packets++;
        fs->bytes += pkt.origlen;
        if (pkt.ts_ns < fs->first_ns) fs->first_ns = pkt.ts_ns;
        if (pkt.ts_ns > fs->last_ns) fs->last_ns = pkt.ts_ns;
        if (have_prev && pkt.ts_ns < prev) { fs->ts_backwards++; an->ts_backwards++; }
        prev = pkt.ts_ns;
        have_prev = 1;
        analyzer_packet(an, &pkt);
        if (g_verbosity >= 2 && fs->packets % 1000000 == 0)
            log_debug("%s: %llu packets", path, (unsigned long long)fs->packets);
    }
    if (rc < 0) {
        snprintf(fs->status, sizeof fs->status, "stopped after %llu packets: %.100s",
                 (unsigned long long)fs->packets, pcap_reader_error(r));
        log_warn("%s: %s", path, fs->status);
    } else if (pcap_reader_truncated(r)) {
        snprintf(fs->status, sizeof fs->status, "truncated (last record incomplete)");
        log_warn("%s: file is truncated; last incomplete record ignored", path);
    } else {
        snprintf(fs->status, sizeof fs->status, "ok");
    }
    uint64_t sk = pcap_reader_skipped(r);
    if (sk) {
        size_t l = strlen(fs->status);
        snprintf(fs->status + l, sizeof fs->status - l, "; %llu bad blocks skipped", (unsigned long long)sk);
    }
    pcap_reader_close(r);
    return 0;
}

flow_t **analyzer_flow_list(const analyzer_t *an, size_t *n)
{
    flow_t **v = xcalloc(an->flows.count ? an->flows.count : 1, sizeof *v);
    size_t k = 0;
    for (flow_chunk_t *c = an->flows.chunks; c; c = c->next)
        for (size_t i = 0; i < c->used; i++) {
            flow_t *f = &c->items[i];
            flow_guess_direction(f);
            v[k++] = f;
        }
    *n = k;
    return v;
}

host_t **analyzer_host_list(const analyzer_t *an, size_t *n)
{
    host_t **v = xcalloc(an->hosts.count ? an->hosts.count : 1, sizeof *v);
    size_t k = 0;
    for (host_chunk_t *c = an->hosts.chunks; c; c = c->next)
        for (size_t i = 0; i < c->used; i++) v[k++] = &c->items[i];
    *n = k;
    return v;
}
