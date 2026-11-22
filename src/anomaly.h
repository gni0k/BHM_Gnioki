#ifndef PCAPREPORT_ANOMALY_H
#define PCAPREPORT_ANOMALY_H

#include <stddef.h>
#include <stdint.h>
#include "analyzer.h"

/*
 * Detection thresholds. Deliberately conservative to keep false positives low;
 * they are heuristics on a passive capture, not proof of an attack.
 */
#define TH_SCAN_VERTICAL_PORTS    50    /* distinct unanswered ports src->dst          */
#define TH_SCAN_HORIZONTAL_HOSTS  25    /* distinct unanswered hosts src->*:port       */
#define TH_SYNFLOOD_HALFOPEN      100   /* unanswered/half-open SYNs to one service    */
#define TH_SYNFLOOD_RATIO         0.5   /* ... as a fraction of all SYNs to it         */
#define TH_RETRANS_WARN           0.02  /* global TCP retransmission rate              */
#define TH_RETRANS_HIGH           0.10
#define TH_RETRANS_MIN_SEGS       100
#define TH_FLOW_RETRANS_RATE      0.05
#define TH_FLOW_RETRANS_MIN_SEGS  20
#define TH_CONN_FAIL_RATIO        0.30
#define TH_CONN_FAIL_MIN          20
#define TH_RST_HOST               100
#define TH_AMP_RATIO              10.0  /* UDP response/request byte ratio             */
#define TH_AMP_MIN_BYTES          (100u * 1024u)
#define TH_UDPFLOOD_PKTS          10000
#define TH_UDPFLOOD_PPS           1000.0
#define TH_BEACON_MIN_FLOWS       8
#define TH_BEACON_MIN_INTERVAL_S  1.0
#define TH_BEACON_MAX_CV          0.15  /* stddev/mean of inter-connection intervals   */
#define TH_ELEPHANT_SHARE         0.5
#define TH_CSUM_OFFLOAD_SHARE     0.9

typedef enum { SEV_INFO = 0, SEV_MEDIUM = 1, SEV_HIGH = 2 } severity_t;

typedef struct {
    severity_t sev;
    char category[48];
    char title[160];
    char detail[768];
} finding_t;

typedef struct {
    uint8_t proto;
    uint16_t port;
    uint64_t flows;
    uint64_t bytes;
    uint64_t pkts;
} port_stat_t;

typedef struct {
    /* derived TCP connection metrics */
    uint64_t tcp_flows, udp_flows;
    uint64_t tcp_syn_flows;       /* flows that started with a SYN in the capture */
    uint64_t tcp_established;
    uint64_t tcp_half_open;       /* SYN (or SYN/ACK) but no completed handshake */
    uint64_t tcp_rejected;        /* answered with RST                           */
    uint64_t tcp_reset;           /* established, ended by RST                   */
    uint64_t tcp_fin_closed;
    uint64_t tcp_midstream;       /* started before capture                      */
    size_t rtt_n;
    double rtt_min_ms, rtt_median_ms, rtt_p95_ms, rtt_max_ms;
    double peak_bps, peak_pps;     /* busiest time bucket                         */
    double avg_bps, avg_pps;
    double duration_s;

    flow_t **flows;               /* sorted by total bytes, descending           */
    size_t nflows;
    host_t **hosts;               /* sorted by total bytes, descending           */
    size_t nhosts;
    port_stat_t *ports;           /* sorted by bytes, descending                 */
    size_t nports;

    finding_t *findings;          /* sorted by severity, descending              */
    size_t nfindings;
    size_t cap_findings;
    size_t sev_count[3];
} results_t;

void results_compute(const analyzer_t *an, results_t *res);
void results_free(results_t *res);
const char *severity_name(severity_t s);
const char *port_service_name(uint8_t proto, uint16_t port);

#endif
