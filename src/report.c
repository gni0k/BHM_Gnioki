#define _POSIX_C_SOURCE 200809L
#include "report.h"
#include "chart.h"
#include "pdf_writer.h"
#include "png_writer.h"
#include "util.h"
#include "version.h"
#include "zcompat.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/* ------------------------------------------------------------- string pool */

typedef struct {
    char **v;
    size_t n, cap;
} pool_t;

static const char *pool_printf(pool_t *p, const char *fmt, ...) PRINTF_LIKE(2, 3);
static const char *pool_printf(pool_t *p, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    char *s = xmalloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    if (p->n == p->cap) {
        p->cap = p->cap ? p->cap * 2 : 128;
        p->v = xreallocarray(p->v, p->cap, sizeof *p->v);
    }
    p->v[p->n++] = s;
    return s;
}

static void pool_free(pool_t *p)
{
    for (size_t i = 0; i < p->n; i++) free(p->v[i]);
    free(p->v);
    memset(p, 0, sizeof *p);
}

/* ------------------------------------------------------------------ layout */

#define ML 40.0
#define MR 40.0
#define MT 48.0
#define MB 56.0
#define CW (PDF_PAGE_W - ML - MR)

#define C_TEXT   RGB(0x0b0b0b)
#define C_TEXT2  RGB(0x52514e)
#define C_RULE   RGB(0xd9d8d3)
#define C_HEAD   RGB(0xf1f0ec)
#define C_ZEBRA  RGB(0xf8f7f4)
#define C_ACCENT RGB(0x2a78d6)
#define C_HIGH   RGB(0xd03b3b)
#define C_MED    RGB(0xec835a)
#define C_INFO   RGB(0x86b6ef)

typedef struct {
    pdf_t *pdf;
    double y;
} doc_t;

static void doc_page(doc_t *d)
{
    pdf_new_page(d->pdf);
    d->y = MT;
}

static void doc_ensure(doc_t *d, double h)
{
    if (d->y + h > PDF_PAGE_H - MB) doc_page(d);
}

static void heading(doc_t *d, const char *num, const char *text)
{
    doc_ensure(d, 70);
    d->y += 14;
    char t[160];
    snprintf(t, sizeof t, "%s  %s", num, text);
    pdf_text(d->pdf, PDF_FONT_BOLD, 15, ML, d->y + 12, t, C_TEXT);
    d->y += 20;
    pdf_line(d->pdf, ML, d->y, ML + CW, d->y, 0.8, C_ACCENT);
    d->y += 12;
}

static void subheading(doc_t *d, const char *text)
{
    doc_ensure(d, 50);
    d->y += 6;
    pdf_text(d->pdf, PDF_FONT_BOLD, 11, ML, d->y + 9, text, C_TEXT);
    d->y += 18;
}

/* Word-wrapped paragraph. */
static void para_at(doc_t *d, double x, double width, pdf_font_t f, double size, const char *text, rgb_t col)
{
    double lh = size * 1.38;
    const char *p = text;
    char line[1024];
    while (*p) {
        size_t len = 0, last_space = 0;
        int has_space = 0;
        while (p[len] && p[len] != '\n' && len < sizeof line - 1) {
            line[len] = p[len];
            line[len + 1] = '\0';
            if (pdf_text_width(f, size, line) > width) break;
            if (p[len] == ' ') { last_space = len; has_space = 1; }
            len++;
        }
        size_t take = len;
        if (p[len] && p[len] != '\n' && has_space) take = last_space;
        if (take == 0) take = len ? len : 1;
        memcpy(line, p, take);
        line[take] = '\0';
        doc_ensure(d, lh);
        pdf_text(d->pdf, f, size, x, d->y + size, line, col);
        d->y += lh;
        p += take;
        while (*p == ' ') p++;
        if (*p == '\n') p++;
    }
}

static void para(doc_t *d, const char *text)
{
    para_at(d, ML, CW, PDF_FONT_REGULAR, 9.5, text, C_TEXT2);
    d->y += 4;
}

/* Truncates s to fit width, appending "..." */
static void fit(char *out, size_t n, const char *s, pdf_font_t f, double size, double width)
{
    snprintf(out, n, "%s", s);
    if (pdf_text_width(f, size, out) <= width) return;
    size_t l = strlen(out);
    while (l > 0) {
        out[--l] = '\0';
        char tmp[512];
        snprintf(tmp, sizeof tmp, "%s...", out);
        if (pdf_text_width(f, size, tmp) <= width) { snprintf(out, n, "%s", tmp); return; }
    }
}

typedef struct {
    const char *head;
    double w;      /* fraction of CW */
    int right;     /* right-aligned */
} col_t;

static void table(doc_t *d, const col_t *cols, size_t nc, const char *const *cells, size_t nr)
{
    const double rh = 15, fs = 8.5;
    double ws[16];
    double x[16];
    double acc = ML;
    for (size_t c = 0; c < nc && c < 16; c++) {
        ws[c] = cols[c].w * CW;
        x[c] = acc;
        acc += ws[c];
    }
    char buf[512];
    int need_head = 1;
    for (size_t r = 0; r <= nr; r++) {
        if (r == nr) break;
        if (d->y + rh * (need_head ? 2 : 1) > PDF_PAGE_H - MB) { doc_page(d); need_head = 1; }
        if (need_head) {
            pdf_fill_rect(d->pdf, ML, d->y, CW, rh, C_HEAD);
            for (size_t c = 0; c < nc; c++) {
                fit(buf, sizeof buf, cols[c].head, PDF_FONT_BOLD, fs, ws[c] - 8);
                double tx = cols[c].right ? x[c] + ws[c] - 4 - pdf_text_width(PDF_FONT_BOLD, fs, buf) : x[c] + 4;
                pdf_text(d->pdf, PDF_FONT_BOLD, fs, tx, d->y + 10.5, buf, C_TEXT);
            }
            d->y += rh;
            need_head = 0;
        }
        if (r % 2 == 1) pdf_fill_rect(d->pdf, ML, d->y, CW, rh, C_ZEBRA);
        for (size_t c = 0; c < nc; c++) {
            const char *s = cells[r * nc + c] ? cells[r * nc + c] : "";
            fit(buf, sizeof buf, s, PDF_FONT_REGULAR, fs, ws[c] - 8);
            double tx = cols[c].right ? x[c] + ws[c] - 4 - pdf_text_width(PDF_FONT_REGULAR, fs, buf) : x[c] + 4;
            pdf_text(d->pdf, PDF_FONT_REGULAR, fs, tx, d->y + 10.5, buf, C_TEXT);
        }
        d->y += rh;
    }
    pdf_line(d->pdf, ML, d->y, ML + CW, d->y, 0.5, C_RULE);
    d->y += 10;
}

/* Key/value two-column table. */
static void kv_table(doc_t *d, const char *const *kv, size_t n)
{
    static const col_t cols[] = {{"Metric", 0.55, 0}, {"Value", 0.45, 1}};
    table(d, cols, 2, kv, n);
}

static void tiles(doc_t *d, const char *const *lab, const char *const *val, size_t n)
{
    const size_t per = 4;
    const double gap = 8, h = 46;
    double w = (CW - gap * (per - 1)) / per;
    for (size_t i = 0; i < n; i++) {
        size_t r = i / per, c = i % per;
        if (c == 0) doc_ensure(d, h + gap);
        double x = ML + c * (w + gap), y = d->y;
        pdf_fill_rect(d->pdf, x, y, w, h, C_HEAD);
        pdf_fill_rect(d->pdf, x, y, 2.5, h, C_ACCENT);
        pdf_text(d->pdf, PDF_FONT_REGULAR, 8, x + 10, y + 15, lab[i], C_TEXT2);
        char b[64];
        fit(b, sizeof b, val[i], PDF_FONT_BOLD, 14, w - 16);
        pdf_text(d->pdf, PDF_FONT_BOLD, 14, x + 10, y + 36, b, C_TEXT);
        if (c == per - 1 || i == n - 1) d->y += h + gap;
        (void)r;
    }
    d->y += 4;
}

static void figure(doc_t *d, int img, const canvas_t *cv, const char *caption)
{
    double w = CW, h = CW * cv->h / cv->w;
    doc_ensure(d, h + 22);
    pdf_draw_image(d->pdf, img, ML, d->y, w, h);
    pdf_line(d->pdf, ML, d->y, ML + w, d->y, 0.4, C_RULE);
    pdf_line(d->pdf, ML, d->y + h, ML + w, d->y + h, 0.4, C_RULE);
    d->y += h + 4;
    if (caption) para_at(d, ML, CW, PDF_FONT_REGULAR, 8, caption, C_TEXT2);
    d->y += 8;
}

/* ------------------------------------------------------------------ charts */

enum { CH_THROUGHPUT, CH_PPS, CH_PROTO, CH_SIZES, CH_TALKERS, CH_PORTS, CH_FLAGS, CH_TCPEV, CH_N };

typedef struct {
    const char *file;
    const char *caption;
    canvas_t cv;
    int img;
} chart_out_t;

static const char *svc_label(pool_t *pool, uint8_t proto, uint16_t port)
{
    const char *n = port_service_name(proto, port);
    return n ? pool_printf(pool, "%s/%u (%s)", proto == PROTO_TCP ? "tcp" : "udp", port, n)
             : pool_printf(pool, "%s/%u", proto == PROTO_TCP ? "tcp" : "udp", port);
}

static void build_charts(const analyzer_t *an, const results_t *res, size_t top, pool_t *pool, chart_out_t *ch)
{
    const timeseries_t *ts = an->ts;
    size_t n = ts->n;
    double wsec = ts->width > 0 ? (double)ts->width / 1e9 : 1.0;
    char wb[32];
    fmt_duration(wb, sizeof wb, wsec);
    double *bt = xcalloc(n ? n : 1, sizeof *bt), *bu = xcalloc(n ? n : 1, sizeof *bu), *bo = xcalloc(n ? n : 1, sizeof *bo);
    double *pt = xcalloc(n ? n : 1, sizeof *pt), *pu = xcalloc(n ? n : 1, sizeof *pu), *po = xcalloc(n ? n : 1, sizeof *po);
    double *es = xcalloc(n ? n : 1, sizeof *es), *er = xcalloc(n ? n : 1, sizeof *er), *ee = xcalloc(n ? n : 1, sizeof *ee);
    for (size_t i = 0; i < n; i++) {
        bt[i] = ts->v[i][TS_BYTES_TCP] * 8 / wsec;
        bu[i] = ts->v[i][TS_BYTES_UDP] * 8 / wsec;
        bo[i] = ts->v[i][TS_BYTES_OTHER] * 8 / wsec;
        pt[i] = ts->v[i][TS_PKTS_TCP] / wsec;
        pu[i] = ts->v[i][TS_PKTS_UDP] / wsec;
        po[i] = ts->v[i][TS_PKTS_OTHER] / wsec;
        es[i] = ts->v[i][TS_SYN] / wsec;
        er[i] = ts->v[i][TS_RST] / wsec;
        ee[i] = ts->v[i][TS_RETRANS] / wsec;
    }
    const char *sub = pool_printf(pool, "Stacked by protocol, averaged over %s intervals", wb);
    series_t s3[3] = {{"TCP", COL_SERIES1, bt}, {"UDP", COL_SERIES2, bu}, {"Other", COL_SERIES3, bo}};
    chart_timeline(&ch[CH_THROUGHPUT].cv, "Throughput over time", sub, ts->t0, ts->width, n, s3, 3, 1, YFMT_BITS);
    series_t p3[3] = {{"TCP", COL_SERIES1, pt}, {"UDP", COL_SERIES2, pu}, {"Other", COL_SERIES3, po}};
    chart_timeline(&ch[CH_PPS].cv, "Packet rate over time (packets/s)", sub, ts->t0, ts->width, n, p3, 3, 1, YFMT_COUNT);
    series_t e3[3] = {{"SYN (connection attempts)", COL_SERIES1, es}, {"RST", COL_SERIES2, er},
                      {"Retransmissions", COL_SERIES3, ee}};
    chart_timeline(&ch[CH_TCPEV].cv, "TCP events over time (events/s)",
                   pool_printf(pool, "Per-second rates over %s intervals", wb), ts->t0, ts->width, n, e3, 3, 0,
                   YFMT_COUNT);
    free(bt); free(bu); free(bo); free(pt); free(pu); free(po); free(es); free(er); free(ee);

    /* protocol share */
    {
        static const char *names[] = {"TCP", "UDP", "ICMP / ICMPv6", "Other / non-IP"};
        double v[4];
        const char *vt[4];
        char b[32];
        for (int i = 0; i < 4; i++) {
            v[i] = (double)an->proto_bytes[i];
            vt[i] = pool_printf(pool, "%s (%.1f%%)", fmt_bytes(b, sizeof b, v[i]),
                                an->bytes ? 100.0 * v[i] / (double)an->bytes : 0.0);
        }
        chart_hbar(&ch[CH_PROTO].cv, "Traffic volume by protocol", "Bytes on the wire and share of total",
                   names, v, vt, 4, COL_SERIES1, YFMT_BYTES);
    }
    /* packet sizes */
    {
        double t[SIZE_BINS], u[SIZE_BINS];
        for (int i = 0; i < SIZE_BINS; i++) {
            t[i] = (double)an->size_hist[PROTO_IDX_TCP][i];
            u[i] = (double)an->size_hist[PROTO_IDX_UDP][i];
        }
        series_t s[2] = {{"TCP", COL_SERIES1, t}, {"UDP", COL_SERIES2, u}};
        chart_bars(&ch[CH_SIZES].cv, "Packet size distribution", "Number of packets per frame-length bucket (bytes)",
                   size_bin_labels, SIZE_BINS, s, 2, YFMT_COUNT);
    }
    /* top talkers */
    {
        size_t k = MIN(top, res->nhosts);
        const char **lab = xcalloc(k ? k : 1, sizeof *lab);
        const char **vt = xcalloc(k ? k : 1, sizeof *vt);
        double *v = xcalloc(k ? k : 1, sizeof *v);
        char b[64];
        for (size_t i = 0; i < k; i++) {
            const host_t *h = res->hosts[i];
            lab[i] = pool_printf(pool, "%s", ip_to_str(&h->ip, b, sizeof b));
            v[i] = (double)(h->bytes_sent + h->bytes_recv);
            vt[i] = pool_printf(pool, "%s", fmt_bytes(b, sizeof b, v[i]));
        }
        chart_hbar(&ch[CH_TALKERS].cv, "Top talkers", "IP bytes sent + received per host", lab, v, vt, k,
                   COL_SERIES1, YFMT_BYTES);
        free(lab); free(vt); free(v);
    }
    /* top services */
    {
        size_t k = MIN(top, res->nports);
        const char **lab = xcalloc(k ? k : 1, sizeof *lab);
        const char **vt = xcalloc(k ? k : 1, sizeof *vt);
        double *v = xcalloc(k ? k : 1, sizeof *v);
        char b[32];
        for (size_t i = 0; i < k; i++) {
            lab[i] = svc_label(pool, res->ports[i].proto, res->ports[i].port);
            v[i] = (double)res->ports[i].bytes;
            vt[i] = pool_printf(pool, "%s, %" PRIu64 " flows", fmt_bytes(b, sizeof b, v[i]), res->ports[i].flows);
        }
        chart_hbar(&ch[CH_PORTS].cv, "Top services (server port)", "Bytes per service port; probe flows excluded",
                   lab, v, vt, k, COL_SERIES1, YFMT_BYTES);
        free(lab); free(vt); free(v);
    }
    /* TCP flags */
    {
        static const char *names[] = {"SYN", "SYN-ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "ACK only"};
        double v[9] = {
            (double)(an->tcp_flag_counts[1] - MIN(an->tcp_flag_counts[1], an->tcp_synack)),
            (double)an->tcp_synack,
            (double)an->tcp_flag_counts[0], (double)an->tcp_flag_counts[2], (double)an->tcp_flag_counts[3],
            (double)an->tcp_flag_counts[5], (double)an->tcp_flag_counts[6], (double)an->tcp_flag_counts[7],
            (double)an->tcp_pure_ack};
        series_t s = {"Segments", COL_SERIES1, v};
        chart_bars(&ch[CH_FLAGS].cv, "TCP flags", "Number of TCP segments carrying each flag", names, 9, &s, 1,
                   YFMT_COUNT);
    }
    ch[CH_THROUGHPUT].file = "01_throughput.png";
    ch[CH_PPS].file = "02_packet_rate.png";
    ch[CH_PROTO].file = "03_protocols.png";
    ch[CH_SIZES].file = "04_packet_sizes.png";
    ch[CH_TALKERS].file = "05_top_talkers.png";
    ch[CH_PORTS].file = "06_top_services.png";
    ch[CH_FLAGS].file = "07_tcp_flags.png";
    ch[CH_TCPEV].file = "08_tcp_events.png";
}

/* ------------------------------------------------------------- formatting */

static const char *pct(pool_t *p, uint64_t a, uint64_t b)
{
    return b ? pool_printf(p, "%.1f%%", 100.0 * (double)a / (double)b) : "-";
}

static const char *cnt(pool_t *p, uint64_t v)
{
    char b[32];
    return pool_printf(p, "%s", fmt_count(b, sizeof b, v));
}

static const char *byt(pool_t *p, double v)
{
    char b[32];
    return pool_printf(p, "%s", fmt_bytes(b, sizeof b, v));
}

static const char *flow_state(const flow_t *f)
{
    if (f->proto != PROTO_TCP) return f->pkts[0] && f->pkts[1] ? "bidirectional" : "one-way";
    int si = f->init_dir ^ 1;
    if (!f->init_by_syn) return f->rst_dir_mask ? "mid-stream, reset" : f->fin_dir_mask ? "mid-stream, closed" : "mid-stream";
    if (f->tcp_state != TCPS_ESTABLISHED) return (f->rst_dir_mask & (1u << si)) ? "rejected (RST)" : "unanswered";
    if (f->rst_dir_mask) return "reset";
    if (f->fin_dir_mask == 3) return "closed (FIN)";
    if (f->fin_dir_mask) return "half-closed";
    return "established";
}

/* ------------------------------------------------------------------- PDF */

static void write_pdf(const analyzer_t *an, const results_t *res, const report_opts_t *o, chart_out_t *ch,
                      pool_t *pool, pdf_t *pdf)
{
    doc_t d = {pdf, MT};
    char b1[64], b2[64];
    doc_page(&d);

    /* Title block */
    pdf_fill_rect(pdf, 0, 0, PDF_PAGE_W, 6, C_ACCENT);
    pdf_text(pdf, PDF_FONT_BOLD, 22, ML, d.y + 22, o->title, C_TEXT);
    d.y += 34;
    char gen[64];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(gen, sizeof gen, "%Y-%m-%d %H:%M UTC", &tm);
    pdf_text(pdf, PDF_FONT_REGULAR, 9.5, ML, d.y + 10,
             pool_printf(pool, "Generated %s by pcapreport %s  |  %zu input file(s)", gen, VERSION_STR, an->nfiles),
             C_TEXT2);
    d.y += 18;
    if (an->have_time) {
        pdf_text(pdf, PDF_FONT_REGULAR, 9.5, ML, d.y + 10,
                 pool_printf(pool, "Capture window: %s  -  %s", fmt_time_utc(b1, sizeof b1, an->first_ns),
                             fmt_time_utc(b2, sizeof b2, an->last_ns)),
                 C_TEXT2);
        d.y += 18;
    }
    d.y += 6;

    /* 1. Summary */
    heading(&d, "1", "Executive summary");
    {
        char b[64];
        const char *lab[8] = {"Packets", "Traffic volume", "Capture duration", "Average throughput",
                              "Peak throughput", "Flows (TCP / UDP)", "Hosts", "Findings (high / medium)"};
        const char *val[8];
        val[0] = cnt(pool, an->packets);
        val[1] = byt(pool, (double)an->bytes);
        val[2] = pool_printf(pool, "%s", fmt_duration(b, sizeof b, res->duration_s));
        val[3] = pool_printf(pool, "%s", fmt_rate_bits(b, sizeof b, res->avg_bps));
        val[4] = pool_printf(pool, "%s", fmt_rate_bits(b, sizeof b, res->peak_bps));
        val[5] = pool_printf(pool, "%" PRIu64 " / %" PRIu64, res->tcp_flows, res->udp_flows);
        val[6] = cnt(pool, an->hosts.count);
        val[7] = pool_printf(pool, "%zu / %zu", res->sev_count[SEV_HIGH], res->sev_count[SEV_MEDIUM]);
        tiles(&d, lab, val, 8);
    }
    if (res->nfindings == 0) {
        para(&d, "No anomalies were detected with the configured heuristics. See section 9 for the methods "
                 "applied and their limitations.");
    } else {
        para(&d, pool_printf(pool, "%zu observation(s) were recorded: %zu high, %zu medium and %zu informational. "
                                   "The most important ones:", res->nfindings, res->sev_count[SEV_HIGH],
                             res->sev_count[SEV_MEDIUM], res->sev_count[SEV_INFO]));
        for (size_t i = 0; i < res->nfindings && i < 5; i++) {
            const finding_t *f = &res->findings[i];
            doc_ensure(&d, 14);
            rgb_t c = f->sev == SEV_HIGH ? C_HIGH : f->sev == SEV_MEDIUM ? C_MED : C_INFO;
            pdf_fill_rect(pdf, ML + 4, d.y + 3, 6, 6, c);
            char t[200];
            snprintf(t, sizeof t, "[%s] %s", severity_name(f->sev), f->title);
            para_at(&d, ML + 16, CW - 16, PDF_FONT_REGULAR, 9.5, t, C_TEXT);
        }
        d.y += 4;
    }

    /* 2. Inputs */
    heading(&d, "2", "Capture files");
    {
        static const col_t cols[] = {{"File", 0.30, 0}, {"Format", 0.08, 0}, {"Link type", 0.16, 0},
                                     {"Packets", 0.11, 1}, {"Bytes", 0.11, 1}, {"Status", 0.24, 0}};
        const char **cells = xcalloc(an->nfiles * 6 + 1, sizeof *cells);
        for (size_t i = 0; i < an->nfiles; i++) {
            const file_stats_t *f = &an->files[i];
            const char *base = strrchr(f->path, '/');
            cells[i * 6 + 0] = base ? base + 1 : f->path;
            cells[i * 6 + 1] = f->ok ? f->format : "-";
            cells[i * 6 + 2] = f->ok && f->packets ? pool_printf(pool, "%s%s", linktype_name(f->linktype),
                                                                 f->mixed_linktypes ? " (+mixed)" : "")
                                                   : "-";
            cells[i * 6 + 3] = cnt(pool, f->packets);
            cells[i * 6 + 4] = byt(pool, (double)f->bytes);
            cells[i * 6 + 5] = f->status;
        }
        table(&d, cols, 6, cells, an->nfiles);
        free(cells);
    }

    /* 3. Traffic overview */
    heading(&d, "3", "Traffic overview");
    {
        static const col_t cols[] = {{"Protocol", 0.28, 0}, {"Packets", 0.18, 1}, {"% packets", 0.18, 1},
                                     {"Bytes", 0.18, 1}, {"% bytes", 0.18, 1}};
        static const char *names[] = {"TCP", "UDP", "ICMP / ICMPv6", "Other IP / non-IP"};
        const char *cells[5 * 5];
        for (int i = 0; i < 4; i++) {
            cells[i * 5 + 0] = names[i];
            cells[i * 5 + 1] = cnt(pool, an->proto_pkts[i]);
            cells[i * 5 + 2] = pct(pool, an->proto_pkts[i], an->packets);
            cells[i * 5 + 3] = byt(pool, (double)an->proto_bytes[i]);
            cells[i * 5 + 4] = pct(pool, an->proto_bytes[i], an->bytes);
        }
        cells[20] = "Total (all frames)";
        cells[21] = cnt(pool, an->packets);
        cells[22] = "100%";
        cells[23] = byt(pool, (double)an->bytes);
        cells[24] = "100%";
        table(&d, cols, 5, cells, 5);
    }
    {
        char b[32];
        const char *kv[] = {
            "IPv4 packets", cnt(pool, an->ipv4_pkts),
            "IPv6 packets", cnt(pool, an->ipv6_pkts),
            "Non-IP frames (ARP, LLDP, STP, ...)", cnt(pool, an->non_ip_pkts),
            "IP fragments", cnt(pool, an->fragments),
            "Average frame size", an->packets ? pool_printf(pool, "%.0f B", (double)an->bytes / (double)an->packets) : "-",
            "Average packet rate", pool_printf(pool, "%.1f pkt/s", res->avg_pps),
            "Peak packet rate", pool_printf(pool, "%.1f pkt/s", res->peak_pps),
            "Peak throughput", pool_printf(pool, "%s", fmt_rate_bits(b, sizeof b, res->peak_bps)),
            "Timeline resolution", pool_printf(pool, "%s per interval", fmt_duration(b, sizeof b, an->ts->width / 1e9)),
        };
        kv_table(&d, kv, ARRAY_LEN(kv) / 2);
    }
    figure(&d, ch[CH_THROUGHPUT].img, &ch[CH_THROUGHPUT].cv,
           "Figure 1. Throughput per interval, stacked by transport protocol. Peaks and plateaus show bursts, "
           "bulk transfers or floods; the peak value depends on the interval length.");
    figure(&d, ch[CH_PPS].img, &ch[CH_PPS].cv,
           "Figure 2. Packet rate. A packet-rate peak without a matching throughput peak points to many "
           "small packets (scans, SYN/UDP floods, VoIP).");
    figure(&d, ch[CH_PROTO].img, &ch[CH_PROTO].cv, "Figure 3. Share of bytes by protocol.");
    figure(&d, ch[CH_SIZES].img, &ch[CH_SIZES].cv,
           "Figure 4. Frame size distribution. Bulk transfers concentrate at MTU size; ACK-dominated or "
           "probing traffic concentrates below 128 bytes.");

    /* 4. TCP */
    heading(&d, "4", "TCP analysis");
    {
        const char *kv[] = {
            "TCP flows (5-tuple, bidirectional)", cnt(pool, res->tcp_flows),
            "Connection attempts observed (SYN)", cnt(pool, res->tcp_syn_flows),
            "  established (3-way handshake completed)", pool_printf(pool, "%s (%s)", cnt(pool, res->tcp_established), pct(pool, res->tcp_established, res->tcp_syn_flows)),
            "  unanswered / half-open", pool_printf(pool, "%s (%s)", cnt(pool, res->tcp_half_open), pct(pool, res->tcp_half_open, res->tcp_syn_flows)),
            "  rejected with RST", pool_printf(pool, "%s (%s)", cnt(pool, res->tcp_rejected), pct(pool, res->tcp_rejected, res->tcp_syn_flows)),
            "Flows already running when capture started", cnt(pool, res->tcp_midstream),
            "Sessions closed with FIN / terminated by RST", pool_printf(pool, "%s / %s", cnt(pool, res->tcp_fin_closed), cnt(pool, res->tcp_reset)),
            "Handshake RTT min / median / p95 / max",
            res->rtt_n ? pool_printf(pool, "%.2f / %.2f / %.2f / %.2f ms", res->rtt_min_ms, res->rtt_median_ms, res->rtt_p95_ms, res->rtt_max_ms) : "n/a",
            "Data segments", cnt(pool, an->tcp_data_segs),
            "Retransmitted / out-of-order segments", pool_printf(pool, "%s (%s)", cnt(pool, an->tcp_retrans), pct(pool, an->tcp_retrans, an->tcp_data_segs)),
            "Sequence gaps (lost before capture point)", cnt(pool, an->tcp_seq_gaps),
            "Zero-window advertisements", cnt(pool, an->tcp_zero_win),
            "Invalid flag combinations", cnt(pool, an->tcp_syn_fin + an->tcp_syn_rst + an->tcp_null + an->tcp_xmas + an->tcp_fin_noack),
        };
        kv_table(&d, kv, ARRAY_LEN(kv) / 2);
    }
    para(&d, "Handshake RTT is measured from the client's last SYN to its ACK of the SYN/ACK, so it is the full "
             "round trip regardless of where the capture was taken. Retransmissions are detected per direction "
             "as segments whose sequence range was already seen (keep-alives excluded).");
    figure(&d, ch[CH_FLAGS].img, &ch[CH_FLAGS].cv,
           "Figure 5. TCP flag usage. In healthy traffic SYN and SYN-ACK counts are similar and RST is rare.");
    figure(&d, ch[CH_TCPEV].img, &ch[CH_TCPEV].cv,
           "Figure 6. TCP control events over time. SYN bursts without matching traffic indicate scans or floods; "
           "retransmission bursts indicate congestion or loss.");

    /* 5. UDP */
    heading(&d, "5", "UDP analysis");
    {
        uint64_t one_way = 0;
        for (size_t i = 0; i < res->nflows; i++)
            if (res->flows[i]->proto == PROTO_UDP && (!res->flows[i]->pkts[0] || !res->flows[i]->pkts[1])) one_way++;
        const char *kv[] = {
            "UDP flows", cnt(pool, res->udp_flows),
            "  of which one-way (no reply observed)", pool_printf(pool, "%s (%s)", cnt(pool, one_way), pct(pool, one_way, res->udp_flows)),
            "UDP packets", cnt(pool, an->proto_pkts[PROTO_IDX_UDP]),
            "UDP bytes", byt(pool, (double)an->proto_bytes[PROTO_IDX_UDP]),
        };
        kv_table(&d, kv, ARRAY_LEN(kv) / 2);
        static const col_t cols[] = {{"UDP service", 0.40, 0}, {"Flows", 0.20, 1}, {"Packets", 0.20, 1}, {"Bytes", 0.20, 1}};
        const char **cells = xcalloc(o->top_n * 4 + 1, sizeof *cells);
        size_t r = 0;
        for (size_t i = 0; i < res->nports && r < o->top_n; i++) {
            if (res->ports[i].proto != PROTO_UDP) continue;
            cells[r * 4 + 0] = svc_label(pool, PROTO_UDP, res->ports[i].port);
            cells[r * 4 + 1] = cnt(pool, res->ports[i].flows);
            cells[r * 4 + 2] = cnt(pool, res->ports[i].pkts);
            cells[r * 4 + 3] = byt(pool, (double)res->ports[i].bytes);
            r++;
        }
        if (r) table(&d, cols, 4, cells, r);
        free(cells);
    }

    /* 6. Hosts */
    heading(&d, "6", "Top talkers");
    {
        static const col_t cols[] = {{"Host", 0.34, 0}, {"Sent", 0.15, 1}, {"Received", 0.15, 1},
                                     {"Pkts sent", 0.12, 1}, {"Pkts recv", 0.12, 1}, {"Share", 0.12, 1}};
        size_t k = MIN(o->top_n, res->nhosts);
        const char **cells = xcalloc(k * 6 + 1, sizeof *cells);
        uint64_t total = 0;
        for (size_t i = 0; i < res->nhosts; i++) total += res->hosts[i]->bytes_sent;
        for (size_t i = 0; i < k; i++) {
            const host_t *h = res->hosts[i];
            cells[i * 6 + 0] = pool_printf(pool, "%s", ip_to_str(&h->ip, b1, sizeof b1));
            cells[i * 6 + 1] = byt(pool, (double)h->bytes_sent);
            cells[i * 6 + 2] = byt(pool, (double)h->bytes_recv);
            cells[i * 6 + 3] = cnt(pool, h->pkts_sent);
            cells[i * 6 + 4] = cnt(pool, h->pkts_recv);
            cells[i * 6 + 5] = pct(pool, h->bytes_sent + h->bytes_recv, total);
        }
        table(&d, cols, 6, cells, k);
        free(cells);
        para(&d, "Share = (sent + received) / total bytes sent by all hosts; it can exceed 100% in sum because "
                 "every byte is counted for both endpoints.");
    }
    figure(&d, ch[CH_TALKERS].img, &ch[CH_TALKERS].cv, "Figure 7. Hosts with the largest traffic volume.");

    /* 7. Services */
    heading(&d, "7", "Services and flows");
    figure(&d, ch[CH_PORTS].img, &ch[CH_PORTS].cv,
           "Figure 8. Most used server ports. The server side is the SYN receiver, or the well-known/registered "
           "port when the handshake was not captured.");
    subheading(&d, "Largest flows");
    {
        static const col_t cols[] = {{"Proto", 0.07, 0}, {"Client", 0.25, 0}, {"Server", 0.25, 0},
                                     {"Packets", 0.10, 1}, {"Bytes", 0.11, 1}, {"Duration", 0.10, 1}, {"State", 0.12, 0}};
        size_t k = MIN(o->top_n, res->nflows);
        const char **cells = xcalloc(k * 7 + 1, sizeof *cells);
        char b[32];
        for (size_t i = 0; i < k; i++) {
            const flow_t *f = res->flows[i];
            int v6 = flow_client(f)->family == 6;
            cells[i * 7 + 0] = f->proto == PROTO_TCP ? "TCP" : "UDP";
            cells[i * 7 + 1] = pool_printf(pool, v6 ? "[%s]:%u" : "%s:%u", ip_to_str(flow_client(f), b1, sizeof b1), flow_client_port(f));
            cells[i * 7 + 2] = pool_printf(pool, v6 ? "[%s]:%u" : "%s:%u", ip_to_str(flow_server(f), b2, sizeof b2), flow_server_port(f));
            cells[i * 7 + 3] = cnt(pool, flow_total_pkts(f));
            cells[i * 7 + 4] = byt(pool, (double)flow_total_bytes(f));
            cells[i * 7 + 5] = pool_printf(pool, "%s", fmt_duration(b, sizeof b, (double)(f->last_ns - f->first_ns) / 1e9));
            cells[i * 7 + 6] = flow_state(f);
        }
        table(&d, cols, 7, cells, k);
        free(cells);
    }

    /* 8. Findings */
    heading(&d, "8", "Anomalies and observations");
    if (res->nfindings == 0) para(&d, "No anomalies detected.");
    for (size_t i = 0; i < res->nfindings; i++) {
        const finding_t *f = &res->findings[i];
        doc_ensure(&d, 48);
        rgb_t c = f->sev == SEV_HIGH ? C_HIGH : f->sev == SEV_MEDIUM ? C_MED : C_INFO;
        const char *sv = severity_name(f->sev);
        double bw = pdf_text_width(PDF_FONT_BOLD, 7.5, sv) + 10;
        pdf_fill_rect(pdf, ML, d.y + 1, bw, 12, c);
        pdf_text(pdf, PDF_FONT_BOLD, 7.5, ML + 5, d.y + 10, sv, f->sev == SEV_HIGH ? RGB(0xffffff) : C_TEXT);
        char t[220];
        snprintf(t, sizeof t, "%s  -  %s", f->category, f->title);
        char tf[220];
        fit(tf, sizeof tf, t, PDF_FONT_BOLD, 10, CW - bw - 8);
        pdf_text(pdf, PDF_FONT_BOLD, 10, ML + bw + 8, d.y + 10.5, tf, C_TEXT);
        d.y += 17;
        para_at(&d, ML + bw + 8, CW - bw - 8, PDF_FONT_REGULAR, 9, f->detail, C_TEXT2);
        d.y += 7;
    }

    /* 9. Method */
    heading(&d, "9", "Methodology and limitations");
    {
        const char *kv[] = {
            "Malformed packets", cnt(pool, an->malformed_pkts),
            "Truncated by snaplen (not analysable at L4)", pool_printf(pool, "%s (%s)", cnt(pool, an->snap_truncated_pkts), cnt(pool, an->snap_unparsed_pkts)),
            "Unsupported link-layer frames", cnt(pool, an->unsupported_link_pkts),
            "IPv4 header checksums verified / bad", pool_printf(pool, "%s / %s", cnt(pool, an->ip_csum_checked), cnt(pool, an->ip_csum_bad)),
            "TCP/UDP checksums verified / bad", pool_printf(pool, "%s / %s", cnt(pool, an->l4_csum_checked), cnt(pool, an->l4_csum_bad)),
            "Flows tracked / limit", pool_printf(pool, "%s / %s", cnt(pool, an->flows.count), cnt(pool, an->flows.limit)),
            "Compression backend", z_backend(),
        };
        kv_table(&d, kv, ARRAY_LEN(kv) / 2);
    }
    para(&d, "Files are read sequentially record by record (classic pcap in both byte orders with micro- or "
             "nanosecond timestamps, and pcapng), so memory use does not depend on file size. Supported link "
             "layers: Ethernet (with 802.1Q/QinQ, PPPoE, MPLS), Linux cooked v1/v2, raw IPv4/IPv6 and BSD loopback. "
             "IPv4 and IPv6 (including extension headers) are decoded; fragments are counted but not reassembled.");
    para(&d, pool_printf(pool, "Flows are bidirectional 5-tuples. Detections are threshold heuristics on "
                               "passively observed traffic: vertical scan >= %d unanswered ports per target, sweep >= %d hosts per port, "
                               "SYN flood >= %d half-open SYNs to one service (>= %.0f%% of its SYNs), "
                               "retransmissions >= %.0f%%, beaconing >= %d connections with interval jitter <= %.0f%%, "
                               "UDP amplification response/request ratio >= %.0f.",
                         TH_SCAN_VERTICAL_PORTS, TH_SCAN_HORIZONTAL_HOSTS, TH_SYNFLOOD_HALFOPEN,
                         TH_SYNFLOOD_RATIO * 100, TH_RETRANS_WARN * 100, TH_BEACON_MIN_FLOWS, TH_BEACON_MAX_CV * 100,
                         TH_AMP_RATIO));
    para(&d, "Limitations: encrypted payloads are not inspected; findings indicate patterns worth investigating, "
             "not proof of malicious intent. Bad checksums on locally sent packets are usually caused by NIC "
             "offloading. Packets the capture dropped cannot be distinguished from network loss, except via the "
             "sequence-gap counter.");
}

/* ------------------------------------------------------------------ entry */

int report_generate(const analyzer_t *an, const results_t *res, const report_opts_t *o)
{
    if (mkdir_p(o->outdir) != 0) {
        log_error("cannot create output directory '%s': %s", o->outdir, strerror(errno));
        return -1;
    }
    pool_t pool = {0};
    chart_out_t ch[CH_N];
    memset(ch, 0, sizeof ch);
    build_charts(an, res, o->top_n, &pool, ch);

    int rc = 0;
    if (o->want_png) {
        for (int i = 0; i < CH_N; i++) {
            char *path = path_join(o->outdir, ch[i].file);
            if (png_write(&ch[i].cv, path) != 0) {
                log_error("cannot write %s: %s", path, strerror(errno));
                rc = -1;
            } else {
                log_info("wrote %s", path);
            }
            free(path);
        }
    }
    if (o->want_pdf) {
        pdf_t *pdf = pdf_new(o->title);
        for (int i = 0; i < CH_N; i++) ch[i].img = pdf_add_image(pdf, &ch[i].cv);
        pdf_set_footer(pdf, pool_printf(&pool, "%s  -  pcapreport %s", o->title, VERSION_STR));
        write_pdf(an, res, o, ch, &pool, pdf);
        char *path = path_join(o->outdir, "report.pdf");
        if (pdf_save(pdf, path) != 0) {
            log_error("cannot write %s: %s", path, strerror(errno));
            rc = -1;
        } else {
            log_info("wrote %s (%zu pages)", path, pdf_page_count(pdf));
        }
        free(path);
        pdf_free(pdf);
    }
    for (int i = 0; i < CH_N; i++) canvas_free(&ch[i].cv);
    pool_free(&pool);
    return rc;
}

void report_print_summary(FILE *fp, const analyzer_t *an, const results_t *res)
{
    char b1[32], b2[32], b3[32];
    fprintf(fp, "== pcapreport summary ==\n");
    fprintf(fp, "files: %zu  packets: %s  bytes: %s  duration: %s\n", an->nfiles,
            fmt_count(b1, sizeof b1, an->packets), fmt_bytes(b2, sizeof b2, (double)an->bytes),
            fmt_duration(b3, sizeof b3, res->duration_s));
    fprintf(fp, "tcp: %" PRIu64 " pkts / %" PRIu64 " flows   udp: %" PRIu64 " pkts / %" PRIu64
            " flows   icmp: %" PRIu64 "   other/non-IP: %" PRIu64 "\n",
            an->proto_pkts[PROTO_IDX_TCP], res->tcp_flows, an->proto_pkts[PROTO_IDX_UDP], res->udp_flows,
            an->proto_pkts[PROTO_IDX_ICMP], an->proto_pkts[PROTO_IDX_OTHER]);
    fprintf(fp, "tcp connections: %" PRIu64 " attempts, %" PRIu64 " established, %" PRIu64 " half-open, %" PRIu64
            " rejected; retransmissions %" PRIu64 "/%" PRIu64 " data segments\n",
            res->tcp_syn_flows, res->tcp_established, res->tcp_half_open, res->tcp_rejected, an->tcp_retrans,
            an->tcp_data_segs);
    if (res->rtt_n)
        fprintf(fp, "handshake rtt: median %.2f ms, p95 %.2f ms (%zu samples)\n", res->rtt_median_ms,
                res->rtt_p95_ms, res->rtt_n);
    fprintf(fp, "malformed: %" PRIu64 "  non-ip: %" PRIu64 "  unsupported link: %" PRIu64 "\n",
            an->malformed_pkts, an->non_ip_pkts, an->unsupported_link_pkts);
    for (size_t i = 0; i < an->nfiles; i++)
        fprintf(fp, "file %s: %s, %" PRIu64 " packets\n", an->files[i].path, an->files[i].status,
                an->files[i].packets);
    fprintf(fp, "findings: %zu\n", res->nfindings);
    for (size_t i = 0; i < res->nfindings; i++)
        fprintf(fp, "  [%-6s] %s: %s\n", severity_name(res->findings[i].sev), res->findings[i].category,
                res->findings[i].title);
}
