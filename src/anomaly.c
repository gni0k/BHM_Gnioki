#define _POSIX_C_SOURCE 200809L
#include "anomaly.h"
#include "util.h"

#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

const char *severity_name(severity_t s)
{
    switch (s) {
    case SEV_HIGH: return "HIGH";
    case SEV_MEDIUM: return "MEDIUM";
    default: return "INFO";
    }
}

const char *port_service_name(uint8_t proto, uint16_t port)
{
    static const struct { uint16_t port; uint8_t proto; const char *name; } tbl[] = {
        {20, 6, "ftp-data"}, {21, 6, "ftp"}, {22, 6, "ssh"}, {23, 6, "telnet"}, {25, 6, "smtp"},
        {53, 6, "dns"}, {53, 17, "dns"}, {67, 17, "dhcp"}, {68, 17, "dhcp"}, {69, 17, "tftp"},
        {80, 6, "http"}, {88, 6, "kerberos"}, {88, 17, "kerberos"}, {110, 6, "pop3"},
        {123, 17, "ntp"}, {135, 6, "msrpc"}, {137, 17, "netbios-ns"}, {138, 17, "netbios-dgm"},
        {139, 6, "netbios-ssn"}, {143, 6, "imap"}, {161, 17, "snmp"}, {162, 17, "snmptrap"},
        {179, 6, "bgp"}, {389, 6, "ldap"}, {389, 17, "cldap"}, {443, 6, "https"}, {443, 17, "quic"},
        {445, 6, "smb"}, {465, 6, "smtps"}, {500, 17, "isakmp"}, {514, 17, "syslog"},
        {520, 17, "rip"}, {587, 6, "submission"}, {636, 6, "ldaps"}, {853, 6, "dns-tls"},
        {993, 6, "imaps"}, {995, 6, "pop3s"}, {1194, 17, "openvpn"}, {1433, 6, "mssql"},
        {1521, 6, "oracle"}, {1883, 6, "mqtt"}, {1900, 17, "ssdp"}, {2049, 6, "nfs"},
        {3306, 6, "mysql"}, {3389, 6, "rdp"}, {3478, 17, "stun"}, {4500, 17, "ipsec-nat"},
        {5060, 17, "sip"}, {5060, 6, "sip"}, {5353, 17, "mdns"}, {5355, 17, "llmnr"},
        {5432, 6, "postgres"}, {5672, 6, "amqp"}, {5900, 6, "vnc"}, {6379, 6, "redis"},
        {6443, 6, "k8s-api"}, {8080, 6, "http-alt"}, {8443, 6, "https-alt"}, {9092, 6, "kafka"},
        {9200, 6, "elastic"}, {11211, 17, "memcached"}, {11211, 6, "memcached"},
        {27017, 6, "mongodb"}, {51820, 17, "wireguard"},
    };
    for (size_t i = 0; i < ARRAY_LEN(tbl); i++)
        if (tbl[i].port == port && tbl[i].proto == proto) return tbl[i].name;
    return NULL;
}

static void add_finding(results_t *r, severity_t sev, const char *cat, const char *title,
                        const char *fmt, ...) PRINTF_LIKE(5, 6);
static void add_finding(results_t *r, severity_t sev, const char *cat, const char *title,
                        const char *fmt, ...)
{
    if (r->nfindings == r->cap_findings) {
        r->cap_findings = r->cap_findings ? r->cap_findings * 2 : 16;
        r->findings = xreallocarray(r->findings, r->cap_findings, sizeof *r->findings);
    }
    finding_t *f = &r->findings[r->nfindings++];
    memset(f, 0, sizeof *f);
    f->sev = sev;
    snprintf(f->category, sizeof f->category, "%s", cat);
    snprintf(f->title, sizeof f->title, "%s", title);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->detail, sizeof f->detail, fmt, ap);
    va_end(ap);
    r->sev_count[sev]++;
}

/* --------------------------------------------------------------- sorting */

static int cmp_flow_bytes(const void *x, const void *y)
{
    const flow_t *a = *(const flow_t *const *)x, *b = *(const flow_t *const *)y;
    uint64_t ba = flow_total_bytes(a), bb = flow_total_bytes(b);
    return ba < bb ? 1 : ba > bb ? -1 : 0;
}
static int cmp_host_bytes(const void *x, const void *y)
{
    const host_t *a = *(const host_t *const *)x, *b = *(const host_t *const *)y;
    uint64_t ba = a->bytes_sent + a->bytes_recv, bb = b->bytes_sent + b->bytes_recv;
    return ba < bb ? 1 : ba > bb ? -1 : 0;
}
static int cmp_port_bytes(const void *x, const void *y)
{
    const port_stat_t *a = x, *b = y;
    return a->bytes < b->bytes ? 1 : a->bytes > b->bytes ? -1 : 0;
}
static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return a < b ? -1 : a > b;
}

/* Probe records for scan / flood detection. */
typedef struct {
    ip_addr_t src, dst;
    uint16_t port;
    uint8_t proto;
    uint8_t answered;  /* connection established / data returned */
    uint32_t syns;
    int64_t ts;
} probe_t;

static int cmp_probe_vertical(const void *x, const void *y)
{
    const probe_t *a = x, *b = y;
    if (a->proto != b->proto) return a->proto - b->proto;
    int c = ip_cmp(&a->src, &b->src);
    if (c) return c;
    if ((c = ip_cmp(&a->dst, &b->dst))) return c;
    return (int)a->port - (int)b->port;
}
static int cmp_probe_horizontal(const void *x, const void *y)
{
    const probe_t *a = x, *b = y;
    if (a->proto != b->proto) return a->proto - b->proto;
    int c = ip_cmp(&a->src, &b->src);
    if (c) return c;
    if (a->port != b->port) return (int)a->port - (int)b->port;
    return ip_cmp(&a->dst, &b->dst);
}
static int cmp_probe_service(const void *x, const void *y)
{
    const probe_t *a = x, *b = y;
    int c = ip_cmp(&a->dst, &b->dst);
    if (c) return c;
    if (a->port != b->port) return (int)a->port - (int)b->port;
    return ip_cmp(&a->src, &b->src);
}
static int cmp_probe_beacon(const void *x, const void *y)
{
    const probe_t *a = x, *b = y;
    int c = cmp_probe_vertical(a, b);
    if (c) return c;
    return a->ts < b->ts ? -1 : a->ts > b->ts;
}

static const char *proto_name(uint8_t p) { return p == PROTO_TCP ? "TCP" : p == PROTO_UDP ? "UDP" : "IP"; }

static int is_tcp_probe(const flow_t *f)
{
    int resp = f->init_dir ^ 1;
    if (f->init_by_syn) return f->tcp_state != TCPS_ESTABLISHED && f->payload[resp] == 0;
    /* stealth probes (NULL/FIN/XMAS) without a real conversation */
    return f->bad_flags > 0 && f->payload[0] == 0 && f->payload[1] == 0;
}

static int is_udp_probe(const flow_t *f)
{
    int resp = f->init_dir ^ 1;
    return f->pkts[f->init_dir] <= 2 && f->pkts[resp] == 0;
}

/* ------------------------------------------------------------- detectors */

static void detect_scans(results_t *r, probe_t *pr, size_t n)
{
    char s1[64], s2[64];
    if (n == 0) return;
    qsort(pr, n, sizeof *pr, cmp_probe_vertical);
    size_t reported = 0;
    for (size_t i = 0; i < n;) {
        size_t j = i, ports = 0;
        uint16_t lo = pr[i].port, hi = pr[i].port;
        int64_t t0 = pr[i].ts, t1 = pr[i].ts;
        while (j < n && pr[j].proto == pr[i].proto && ip_cmp(&pr[j].src, &pr[i].src) == 0 &&
               ip_cmp(&pr[j].dst, &pr[i].dst) == 0) {
            if (j == i || pr[j].port != pr[j - 1].port) ports++;
            if (pr[j].port < lo) lo = pr[j].port;
            if (pr[j].port > hi) hi = pr[j].port;
            if (pr[j].ts < t0) t0 = pr[j].ts;
            if (pr[j].ts > t1) t1 = pr[j].ts;
            j++;
        }
        if (ports >= TH_SCAN_VERTICAL_PORTS) {
            if (reported < 10) {
                double dur = (double)(t1 - t0) / 1e9;
                char title[160];
                snprintf(title, sizeof title, "%s port scan: %s -> %s", proto_name(pr[i].proto),
                         ip_to_str(&pr[i].src, s1, sizeof s1), ip_to_str(&pr[i].dst, s2, sizeof s2));
                add_finding(r, SEV_HIGH, "Port scan", title,
                            "%zu distinct destination ports (range %u-%u) probed without an established "
                            "session within %.1f s (%.0f probes/s). Typical of a vertical port scan "
                            "(e.g. nmap -sS / -sU).",
                            ports, lo, hi, dur, dur > 0 ? (double)(j - i) / dur : (double)(j - i));
            }
            reported++;
        }
        i = j;
    }
    if (reported > 10)
        add_finding(r, SEV_HIGH, "Port scan", "Additional vertical scans",
                    "%zu further source/target pairs exceeded the scan threshold (not listed).", reported - 10);

    qsort(pr, n, sizeof *pr, cmp_probe_horizontal);
    reported = 0;
    for (size_t i = 0; i < n;) {
        size_t j = i, hosts = 0;
        while (j < n && pr[j].proto == pr[i].proto && ip_cmp(&pr[j].src, &pr[i].src) == 0 &&
               pr[j].port == pr[i].port) {
            if (j == i || ip_cmp(&pr[j].dst, &pr[j - 1].dst) != 0) hosts++;
            j++;
        }
        if (hosts >= TH_SCAN_HORIZONTAL_HOSTS) {
            if (reported < 10) {
                char title[160];
                const char *svc = port_service_name(pr[i].proto, pr[i].port);
                snprintf(title, sizeof title, "Host sweep on %s/%u%s%s%s from %s", proto_name(pr[i].proto),
                         pr[i].port, svc ? " (" : "", svc ? svc : "", svc ? ")" : "",
                         ip_to_str(&pr[i].src, s1, sizeof s1));
                add_finding(r, SEV_HIGH, "Network sweep", title,
                            "%zu distinct hosts probed on the same port without an established session "
                            "(horizontal scan / worm-like propagation).", hosts);
            }
            reported++;
        }
        i = j;
    }
}

static void detect_syn_flood(results_t *r, probe_t *pr, size_t n)
{
    char s1[64];
    if (n == 0) return;
    qsort(pr, n, sizeof *pr, cmp_probe_service);
    for (size_t i = 0; i < n;) {
        size_t j = i, srcs = 0;
        uint64_t total = 0, half = 0;
        int64_t t0 = pr[i].ts, t1 = pr[i].ts;
        while (j < n && ip_cmp(&pr[j].dst, &pr[i].dst) == 0 && pr[j].port == pr[i].port) {
            if (j == i || ip_cmp(&pr[j].src, &pr[j - 1].src) != 0) srcs++;
            total += pr[j].syns;
            if (!pr[j].answered) half += pr[j].syns;
            if (pr[j].ts < t0) t0 = pr[j].ts;
            if (pr[j].ts > t1) t1 = pr[j].ts;
            j++;
        }
        if (half >= TH_SYNFLOOD_HALFOPEN && (double)half / (double)total >= TH_SYNFLOOD_RATIO &&
            srcs >= 3) {
            double dur = (double)(t1 - t0) / 1e9;
            char title[160];
            snprintf(title, sizeof title, "Possible SYN flood against %s:%u",
                     ip_to_str(&pr[i].dst, s1, sizeof s1), pr[i].port);
            add_finding(r, SEV_HIGH, "SYN flood", title,
                        "%" PRIu64 " of %" PRIu64 " SYNs (%.0f%%) never completed the handshake, from %zu "
                        "distinct source addresses over %.1f s (%.0f SYN/s).%s",
                        half, total, 100.0 * (double)half / (double)total, srcs, dur,
                        dur > 0 ? (double)total / dur : (double)total,
                        srcs > 50 ? " The large number of sources suggests spoofed or distributed origin." : "");
        }
        i = j;
    }
}

static void detect_beacons(results_t *r, probe_t *pr, size_t n)
{
    char s1[64], s2[64];
    if (n == 0) return;
    qsort(pr, n, sizeof *pr, cmp_probe_beacon);
    size_t reported = 0;
    for (size_t i = 0; i < n;) {
        size_t j = i;
        while (j < n && pr[j].proto == pr[i].proto && ip_cmp(&pr[j].src, &pr[i].src) == 0 &&
               ip_cmp(&pr[j].dst, &pr[i].dst) == 0 && pr[j].port == pr[i].port)
            j++;
        size_t k = j - i;
        if (k >= TH_BEACON_MIN_FLOWS) {
            double sum = 0, sq = 0;
            for (size_t m = i + 1; m < j; m++) sum += (double)(pr[m].ts - pr[m - 1].ts) / 1e9;
            double mean = sum / (double)(k - 1);
            for (size_t m = i + 1; m < j; m++) {
                double d = (double)(pr[m].ts - pr[m - 1].ts) / 1e9 - mean;
                sq += d * d;
            }
            double cv = mean > 0 ? sqrt(sq / (double)(k - 1)) / mean : 1e9;
            if (mean >= TH_BEACON_MIN_INTERVAL_S && cv <= TH_BEACON_MAX_CV) {
                if (reported < 5) {
                    char title[160];
                    snprintf(title, sizeof title, "Periodic connections %s -> %s:%u/%s",
                             ip_to_str(&pr[i].src, s1, sizeof s1), ip_to_str(&pr[i].dst, s2, sizeof s2),
                             pr[i].port, proto_name(pr[i].proto));
                    add_finding(r, SEV_MEDIUM, "Beaconing", title,
                                "%zu connections at a regular interval of %.1f s (jitter %.1f%%). Can be "
                                "legitimate polling (monitoring, updates) but is also typical of malware "
                                "command-and-control beaconing.",
                                k, mean, cv * 100.0);
                }
                reported++;
            }
        }
        i = j;
    }
}

static int is_amp_port(uint16_t p)
{
    static const uint16_t ports[] = {17, 19, 53, 69, 111, 123, 137, 161, 389, 520, 1900, 3283, 3702,
                                     5353, 5683, 10001, 11211};
    for (size_t i = 0; i < ARRAY_LEN(ports); i++)
        if (ports[i] == p) return 1;
    return 0;
}

static double percentile(const double *v, size_t n, double p)
{
    if (n == 0) return 0;
    double idx = p * (double)(n - 1);
    size_t lo = (size_t)idx;
    size_t hi = lo + 1 < n ? lo + 1 : lo;
    double fr = idx - (double)lo;
    return v[lo] * (1 - fr) + v[hi] * fr;
}

static int cmp_finding(const void *x, const void *y)
{
    const finding_t *a = x, *b = y;
    if (a->sev != b->sev) return (int)b->sev - (int)a->sev;
    return strcmp(a->category, b->category);
}

static const char *perr_name(int bit)
{
    static const char *n[] = {"link header truncated", "IP header truncated", "invalid IP header",
                              "inconsistent IP length", "TCP/UDP header truncated", "invalid TCP data offset",
                              "invalid UDP length", "bad IPv4 header checksum", "bad TCP/UDP checksum",
                              "broken IPv6 extension header chain"};
    return bit >= 0 && (size_t)bit < ARRAY_LEN(n) ? n[bit] : "other";
}

/* ----------------------------------------------------------------- main */

void results_compute(const analyzer_t *an, results_t *r)
{
    memset(r, 0, sizeof *r);
    char s1[64], s2[64], b1[32], b2[32];

    r->flows = analyzer_flow_list(an, &r->nflows);
    r->hosts = analyzer_host_list(an, &r->nhosts);
    qsort(r->flows, r->nflows, sizeof *r->flows, cmp_flow_bytes);
    qsort(r->hosts, r->nhosts, sizeof *r->hosts, cmp_host_bytes);

    r->duration_s = an->have_time ? (double)(an->last_ns - an->first_ns) / 1e9 : 0;
    if (r->duration_s > 0) {
        r->avg_bps = (double)an->bytes * 8.0 / r->duration_s;
        r->avg_pps = (double)an->packets / r->duration_s;
    }
    const timeseries_t *ts = an->ts;
    double wsec = ts->width > 0 ? (double)ts->width / 1e9 : 1;
    for (size_t i = 0; i < ts->n; i++) {
        double b = ts->v[i][TS_BYTES_TCP] + ts->v[i][TS_BYTES_UDP] + ts->v[i][TS_BYTES_OTHER];
        double p = ts->v[i][TS_PKTS_TCP] + ts->v[i][TS_PKTS_UDP] + ts->v[i][TS_PKTS_OTHER];
        if (b * 8 / wsec > r->peak_bps) r->peak_bps = b * 8 / wsec;
        if (p / wsec > r->peak_pps) r->peak_pps = p / wsec;
    }

    /* Per-flow derived metrics, probe lists, port aggregation. */
    double *rtts = xcalloc(r->nflows ? r->nflows : 1, sizeof *rtts);
    probe_t *scan = xcalloc(r->nflows ? r->nflows : 1, sizeof *scan);
    probe_t *svc = xcalloc(r->nflows ? r->nflows : 1, sizeof *svc);
    probe_t *beacon = xcalloc(r->nflows ? r->nflows : 1, sizeof *beacon);
    port_stat_t *ports = xcalloc(2u * 65536u, sizeof *ports);
    size_t nscan = 0, nsvc = 0, nbeacon = 0, nports = 0;
    uint64_t flows_zero_win = 0;
    const flow_t *zw_top = NULL;

    for (size_t i = 0; i < r->nflows; i++) {
        const flow_t *f = r->flows[i];
        int ci = f->init_dir, si = ci ^ 1;
        if (f->proto == PROTO_TCP) {
            r->tcp_flows++;
            if (f->init_by_syn) {
                r->tcp_syn_flows++;
                if (f->tcp_state == TCPS_ESTABLISHED) r->tcp_established++;
                else if (f->rst_dir_mask & (1u << si)) r->tcp_rejected++;
                else r->tcp_half_open++;
                svc[nsvc].src = *flow_client(f);
                svc[nsvc].dst = *flow_server(f);
                svc[nsvc].port = flow_server_port(f);
                svc[nsvc].proto = PROTO_TCP;
                svc[nsvc].syns = f->syn_count[ci] ? f->syn_count[ci] : 1;
                svc[nsvc].answered = f->tcp_state == TCPS_ESTABLISHED || f->payload[si] > 0;
                svc[nsvc].ts = f->first_ns;
                nsvc++;
            } else {
                r->tcp_midstream++;
            }
            if (f->tcp_state == TCPS_ESTABLISHED || !f->init_by_syn) {
                if (f->rst_dir_mask) r->tcp_reset++;
                else if (f->fin_dir_mask) r->tcp_fin_closed++;
            }
            if (f->rtt_ns >= 0) rtts[r->rtt_n++] = (double)f->rtt_ns / 1e6;
            if (f->zero_win[0] + f->zero_win[1] > 0) {
                flows_zero_win++;
                if (!zw_top || f->zero_win[0] + f->zero_win[1] > zw_top->zero_win[0] + zw_top->zero_win[1])
                    zw_top = f;
            }
        } else if (f->proto == PROTO_UDP) {
            r->udp_flows++;
        }
        int probe = f->proto == PROTO_TCP ? is_tcp_probe(f) : is_udp_probe(f);
        if (probe) {
            scan[nscan].src = *flow_client(f);
            scan[nscan].dst = *flow_server(f);
            scan[nscan].port = flow_server_port(f);
            scan[nscan].proto = f->proto;
            scan[nscan].ts = f->first_ns;
            nscan++;
        } else if (f->proto == PROTO_TCP ? f->init_by_syn : 1) {
            beacon[nbeacon].src = *flow_client(f);
            beacon[nbeacon].dst = *flow_server(f);
            beacon[nbeacon].port = flow_server_port(f);
            beacon[nbeacon].proto = f->proto;
            beacon[nbeacon].ts = f->first_ns;
            nbeacon++;
        }
        /* Port aggregation (only for flows that are not probes): direct index per proto/port. */
        if (!probe) {
            size_t k = (size_t)(f->proto == PROTO_UDP) * 65536u + flow_server_port(f);
            ports[k].flows++;
            ports[k].bytes += flow_total_bytes(f);
            ports[k].pkts += flow_total_pkts(f);
        }
    }
    for (size_t k = 0; k < 2u * 65536u; k++) {
        if (!ports[k].flows) continue;
        ports[nports] = ports[k];
        ports[nports].proto = k >= 65536u ? PROTO_UDP : PROTO_TCP;
        ports[nports].port = (uint16_t)(k & 0xFFFFu);
        nports++;
    }
    qsort(ports, nports, sizeof *ports, cmp_port_bytes);
    r->ports = ports;
    r->nports = nports;

    if (r->rtt_n) {
        qsort(rtts, r->rtt_n, sizeof *rtts, cmp_double);
        r->rtt_min_ms = rtts[0];
        r->rtt_max_ms = rtts[r->rtt_n - 1];
        r->rtt_median_ms = percentile(rtts, r->rtt_n, 0.5);
        r->rtt_p95_ms = percentile(rtts, r->rtt_n, 0.95);
    }
    free(rtts);

    detect_scans(r, scan, nscan);
    detect_syn_flood(r, svc, nsvc);
    detect_beacons(r, beacon, nbeacon);
    free(scan);
    free(svc);
    free(beacon);

    /* --- TCP health --- */
    if (an->tcp_data_segs >= TH_RETRANS_MIN_SEGS) {
        double rate = (double)an->tcp_retrans / (double)an->tcp_data_segs;
        if (rate >= TH_RETRANS_WARN) {
            char t[160];
            snprintf(t, sizeof t, "High TCP retransmission rate: %.1f%%", rate * 100);
            add_finding(r, rate >= TH_RETRANS_HIGH ? SEV_HIGH : SEV_MEDIUM, "TCP performance", t,
                        "%" PRIu64 " retransmitted / out-of-order segments out of %" PRIu64 " data segments. "
                        "Indicates packet loss, congestion or a lossy link (healthy LAN traffic is well below 1%%).",
                        an->tcp_retrans, an->tcp_data_segs);
        }
    }
    size_t lossy = 0;
    for (size_t i = 0; i < r->nflows && lossy < 5; i++) {
        const flow_t *f = r->flows[i];
        if (f->proto != PROTO_TCP) continue;
        uint32_t segs = f->data_segs[0] + f->data_segs[1];
        uint32_t re = f->retrans[0] + f->retrans[1];
        if (segs >= TH_FLOW_RETRANS_MIN_SEGS && (double)re / segs >= TH_FLOW_RETRANS_RATE) {
            char t[160];
            snprintf(t, sizeof t, "Lossy TCP connection %s:%u <-> %s:%u",
                     ip_to_str(flow_client(f), s1, sizeof s1), flow_client_port(f),
                     ip_to_str(flow_server(f), s2, sizeof s2), flow_server_port(f));
            add_finding(r, SEV_MEDIUM, "TCP performance", t,
                        "%u of %u data segments (%.1f%%) retransmitted; %s transferred.",
                        re, segs, 100.0 * re / segs, fmt_bytes(b1, sizeof b1, (double)flow_total_bytes(f)));
            lossy++;
        }
    }
    if (an->tcp_data_segs >= TH_RETRANS_MIN_SEGS &&
        (double)an->tcp_seq_gaps / (double)an->tcp_data_segs > 0.01) {
        add_finding(r, SEV_INFO, "Capture quality", "TCP sequence gaps detected",
                    "%" PRIu64 " segments arrived after a gap in sequence space (%.1f%% of data segments). "
                    "Either the network lost packets or the capture itself dropped them (check capture "
                    "interface drop counters); retransmission figures may be affected.",
                    an->tcp_seq_gaps, 100.0 * (double)an->tcp_seq_gaps / (double)an->tcp_data_segs);
    }
    if (r->tcp_syn_flows >= TH_CONN_FAIL_MIN) {
        double fail = (double)(r->tcp_half_open + r->tcp_rejected) / (double)r->tcp_syn_flows;
        if (fail >= TH_CONN_FAIL_RATIO) {
            char t[160];
            snprintf(t, sizeof t, "%.0f%% of TCP connection attempts failed", fail * 100);
            add_finding(r, fail >= 0.6 ? SEV_HIGH : SEV_MEDIUM, "TCP connectivity", t,
                        "%" PRIu64 " attempts unanswered, %" PRIu64 " rejected with RST, out of %" PRIu64
                        ". Causes: scanning, firewalled/closed services, unreachable hosts or SYN floods.",
                        r->tcp_half_open, r->tcp_rejected, r->tcp_syn_flows);
        }
    }
    if (flows_zero_win && zw_top) {
        char t[160];
        snprintf(t, sizeof t, "TCP zero-window conditions in %" PRIu64 " connection(s)", flows_zero_win);
        add_finding(r, SEV_MEDIUM, "TCP performance", t,
                    "%" PRIu64 " zero-window advertisements in total: a receiver could not keep up and "
                    "stalled the sender. Worst: %s:%u <-> %s:%u with %u events.",
                    an->tcp_zero_win, ip_to_str(flow_client(zw_top), s1, sizeof s1), flow_client_port(zw_top),
                    ip_to_str(flow_server(zw_top), s2, sizeof s2), flow_server_port(zw_top),
                    zw_top->zero_win[0] + zw_top->zero_win[1]);
    }

    /* --- Invalid TCP flags --- */
    uint64_t bad = an->tcp_syn_fin + an->tcp_syn_rst + an->tcp_null + an->tcp_xmas + an->tcp_fin_noack;
    if (bad) {
        const host_t *top = NULL;
        for (size_t i = 0; i < r->nhosts; i++)
            if (r->hosts[i]->bad_flags_sent && (!top || r->hosts[i]->bad_flags_sent > top->bad_flags_sent))
                top = r->hosts[i];
        char t[160];
        snprintf(t, sizeof t, "%" PRIu64 " TCP segments with invalid flag combinations", bad);
        add_finding(r, bad >= 10 ? SEV_HIGH : SEV_MEDIUM, "Invalid TCP flags", t,
                    "SYN+FIN: %" PRIu64 ", SYN+RST: %" PRIu64 ", NULL (no flags): %" PRIu64
                    ", XMAS (FIN+PSH+URG): %" PRIu64 ", FIN without ACK: %" PRIu64
                    ". Such segments do not occur in normal stacks and are used for stealth scanning and "
                    "OS fingerprinting.%s%s%s",
                    an->tcp_syn_fin, an->tcp_syn_rst, an->tcp_null, an->tcp_xmas, an->tcp_fin_noack,
                    top ? " Main source: " : "", top ? ip_to_str(&top->ip, s1, sizeof s1) : "", top ? "." : "");
    }

    /* --- Hosts: RST storms, UDP floods, checksum offload heuristics --- */
    size_t rst_rep = 0;
    uint64_t csum_bad_total = 0;
    const host_t *csum_top = NULL;
    for (size_t i = 0; i < r->nhosts; i++) {
        const host_t *h = r->hosts[i];
        csum_bad_total += h->bad_csum_sent;
        if (h->bad_csum_sent && (!csum_top || h->bad_csum_sent > csum_top->bad_csum_sent)) csum_top = h;
        if (h->rst_sent >= TH_RST_HOST && rst_rep < 5) {
            char t[160];
            snprintf(t, sizeof t, "Host %s sent %" PRIu64 " TCP resets", ip_to_str(&h->ip, s1, sizeof s1), h->rst_sent);
            add_finding(r, SEV_MEDIUM, "TCP resets", t,
                        "%.1f%% of its packets were RST segments. Usually the answer of a host to probes on "
                        "closed ports, or a middlebox / application aborting connections.",
                        h->pkts_sent ? 100.0 * (double)h->rst_sent / (double)h->pkts_sent : 0.0);
            rst_rep++;
        }
        double act = (double)(h->last_ns - h->first_ns) / 1e9;
        if (act < 1) act = 1;
        if (h->udp_pkts_recv >= TH_UDPFLOOD_PKTS && (double)h->udp_pkts_recv / act >= TH_UDPFLOOD_PPS &&
            h->udp_pkts_sent * 100 <= h->udp_pkts_recv) {
            char t[160];
            snprintf(t, sizeof t, "Possible UDP flood toward %s", ip_to_str(&h->ip, s1, sizeof s1));
            add_finding(r, SEV_HIGH, "UDP flood", t,
                        "%" PRIu64 " UDP packets received (%.0f pkt/s on average) while the host sent only %"
                        PRIu64 " UDP packets back.",
                        h->udp_pkts_recv, (double)h->udp_pkts_recv / act, h->udp_pkts_sent);
        }
    }

    /* --- UDP amplification --- */
    size_t amp = 0;
    for (size_t i = 0; i < r->nflows && amp < 5; i++) {
        const flow_t *f = r->flows[i];
        if (f->proto != PROTO_UDP) continue;
        int ci = f->init_dir, si = ci ^ 1;
        uint16_t sp = flow_server_port(f);
        if (!is_amp_port(sp) || f->bytes[si] < TH_AMP_MIN_BYTES) continue;
        double ratio = f->bytes[ci] ? (double)f->bytes[si] / (double)f->bytes[ci] : (double)f->bytes[si];
        if (ratio < TH_AMP_RATIO) continue;
        char t[160];
        const char *svcn = port_service_name(PROTO_UDP, sp);
        snprintf(t, sizeof t, "UDP amplification pattern via %s/%u", svcn ? svcn : "udp", sp);
        add_finding(r, SEV_HIGH, "UDP amplification", t,
                    "Reflector %s returned %s to %s for %s of requests (amplification x%.0f). "
                    "If %s did not send these requests, its address is being spoofed by an attacker.",
                    ip_to_str(flow_server(f), s1, sizeof s1), fmt_bytes(b1, sizeof b1, (double)f->bytes[si]),
                    ip_to_str(flow_client(f), s2, sizeof s2), fmt_bytes(b2, sizeof b2, (double)f->bytes[ci]),
                    ratio, s2);
        amp++;
    }

    /* --- Malformed / checksum --- */
    if (an->malformed_pkts) {
        char det[700];
        size_t o = 0;
        o += (size_t)snprintf(det + o, sizeof det - o, "Breakdown:");
        for (int b = 0; b < 10; b++) {
            if (b == 7 || b == 8) continue; /* checksums reported separately */
            if (an->perr_counts[b] && o < sizeof det)
                o += (size_t)snprintf(det + o, sizeof det - o, " %s: %" PRIu64 ";", perr_name(b), an->perr_counts[b]);
        }
        if (o < sizeof det)
            snprintf(det + o, sizeof det - o, " Malformed headers can come from faulty equipment, broken "
                     "capture tooling or deliberately crafted packets (evasion, fuzzing, DoS).");
        char t[160];
        snprintf(t, sizeof t, "%" PRIu64 " malformed packets", an->malformed_pkts);
        add_finding(r, an->malformed_pkts * 1000 > an->packets ? SEV_HIGH : SEV_MEDIUM, "Malformed packets", t, "%s", det);
    }
    if (an->ip_csum_bad + an->l4_csum_bad) {
        double share = csum_top && csum_bad_total ? (double)csum_top->bad_csum_sent / (double)csum_bad_total : 0;
        char t[160];
        snprintf(t, sizeof t, "%" PRIu64 " packets with bad checksums", an->ip_csum_bad + an->l4_csum_bad);
        if (share >= TH_CSUM_OFFLOAD_SHARE)
            add_finding(r, SEV_INFO, "Checksums", t,
                        "IPv4 header: %" PRIu64 "/%" PRIu64 ", TCP/UDP: %" PRIu64 "/%" PRIu64 " verified packets bad. "
                        "%.0f%% come from %s - almost certainly checksum offloading on the capturing host "
                        "(checksums are filled in by the NIC after capture), not a network fault.",
                        an->ip_csum_bad, an->ip_csum_checked, an->l4_csum_bad, an->l4_csum_checked, share * 100,
                        ip_to_str(&csum_top->ip, s1, sizeof s1));
        else
            add_finding(r, SEV_MEDIUM, "Checksums", t,
                        "IPv4 header: %" PRIu64 "/%" PRIu64 ", TCP/UDP: %" PRIu64 "/%" PRIu64 " verified packets bad, "
                        "spread across several senders. Possible corruption on the path or crafted packets "
                        "(if captured on an endpoint, rule out NIC checksum offloading first).",
                        an->ip_csum_bad, an->ip_csum_checked, an->l4_csum_bad, an->l4_csum_checked);
    }
    if (an->land_pkts)
        add_finding(r, SEV_HIGH, "Spoofing", "LAND packets (source == destination)",
                    "%" PRIu64 " packet(s) with identical source and destination address and port - a classic "
                    "DoS pattern that never occurs legitimately.", an->land_pkts);
    if (an->mcast_src_pkts)
        add_finding(r, SEV_MEDIUM, "Spoofing", "Multicast/broadcast source addresses",
                    "%" PRIu64 " packets carry a multicast or broadcast address as source, which is invalid "
                    "and indicates spoofing or misconfiguration.", an->mcast_src_pkts);
    if (an->port0_pkts)
        add_finding(r, SEV_MEDIUM, "Suspicious ports", "Traffic using port 0",
                    "%" PRIu64 " TCP/UDP packets use port 0 (reserved). Seen in OS fingerprinting, "
                    "crafted DoS traffic and reflection attacks.", an->port0_pkts);

    /* --- Capture quality --- */
    if (an->ts_backwards)
        add_finding(r, SEV_INFO, "Capture quality", "Non-monotonic timestamps",
                    "%" PRIu64 " packets have a timestamp earlier than the previous packet in the same file "
                    "(multi-interface capture, clock adjustment or merged files).", an->ts_backwards);
    if (an->ts_implausible)
        add_finding(r, SEV_MEDIUM, "Capture quality", "Implausible timestamps",
                    "%" PRIu64 " packets have timestamps before 1995 or in the future; they were excluded "
                    "from the timeline. The capture clock was probably not set.", an->ts_implausible);
    if (an->snap_truncated_pkts)
        add_finding(r, SEV_INFO, "Capture quality", "Packets truncated by snapshot length",
                    "%" PRIu64 " frames were captured only partially (snaplen); %" PRIu64 " of them could not be "
                    "analysed at transport level. Byte counts use original lengths.",
                    an->snap_truncated_pkts, an->snap_unparsed_pkts);
    if (an->unsupported_link_pkts) {
        char lts[96] = "";
        size_t o = 0;
        for (size_t i = 0; i < an->n_unsupported_linktypes && o < sizeof lts; i++)
            o += (size_t)snprintf(lts + o, sizeof lts - o, "%s%" PRIu64, i ? ", " : "", an->unsupported_linktypes[i]);
        add_finding(r, SEV_MEDIUM, "Capture quality", "Unsupported link-layer types",
                    "%" PRIu64 " packets use link types that are not decoded (LINKTYPE %s) and were counted "
                    "only in totals.", an->unsupported_link_pkts, lts);
    }
    if (an->flows.dropped_pkts || an->hosts.dropped)
        add_finding(r, SEV_MEDIUM, "Analysis limits", "Flow/host table limit reached",
                    "%" PRIu64 " packets belonged to flows beyond the --max-flows limit (%zu) and %" PRIu64
                    " host lookups exceeded --max-hosts (%zu). Totals remain exact; per-flow statistics are "
                    "incomplete. Raise the limits if memory allows.",
                    an->flows.dropped_pkts, an->flows.limit, an->hosts.dropped, an->hosts.limit);
    if (r->nflows && an->bytes >= 1024 * 1024) {
        const flow_t *f = r->flows[0];
        double share = (double)flow_total_bytes(f) / (double)an->bytes;
        if (share >= TH_ELEPHANT_SHARE) {
            char t[160];
            snprintf(t, sizeof t, "Single flow carries %.0f%% of all traffic", share * 100);
            add_finding(r, SEV_INFO, "Traffic profile", t,
                        "%s %s:%u -> %s:%u transferred %s. Large bulk transfers (backups, downloads) are "
                        "common; verify it is expected if data exfiltration is a concern.",
                        proto_name(f->proto), ip_to_str(flow_client(f), s1, sizeof s1), flow_client_port(f),
                        ip_to_str(flow_server(f), s2, sizeof s2), flow_server_port(f),
                        fmt_bytes(b1, sizeof b1, (double)flow_total_bytes(f)));
        }
    }

    if (r->nfindings > 1) qsort(r->findings, r->nfindings, sizeof *r->findings, cmp_finding);
}

void results_free(results_t *r)
{
    free(r->flows);
    free(r->hosts);
    free(r->ports);
    free(r->findings);
    memset(r, 0, sizeof *r);
}
