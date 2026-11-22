#define _POSIX_C_SOURCE 200809L
#include "pcap_reader.h"
#include "util.h"

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Hard sanity limits: anything larger is treated as corruption. */
#define MAX_RECORD_LEN   (16u * 1024u * 1024u)  /* 16 MiB per packet/block */
#define MAX_INTERFACES   4096u
#define IO_BUFFER_SIZE   (1u << 20)

/* pcapng block types */
#define BT_SHB 0x0A0D0D0Au
#define BT_IDB 0x00000001u
#define BT_PB  0x00000002u  /* obsolete Packet Block */
#define BT_SPB 0x00000003u
#define BT_EPB 0x00000006u
#define BYTE_ORDER_MAGIC 0x1A2B3C4Du

typedef struct {
    uint32_t linktype;
    uint32_t snaplen;
    int tsres_pow2;   /* 1: resolution is 2^-tsres, 0: 10^-tsres */
    unsigned tsres;   /* exponent */
    int64_t tsoffset; /* seconds */
} iface_t;

struct pcap_reader {
    FILE *fp;
    int is_stdin;
    char *iobuf;
    pcap_format_t fmt;
    int swap;             /* file byte order differs from little endian reading */
    int big_endian;       /* file is big endian */
    /* classic */
    int nsec;
    uint32_t snaplen;
    uint32_t linktype;
    /* pcapng */
    iface_t *ifaces;
    uint32_t n_ifaces;
    /* record buffer */
    unsigned char *rec;
    size_t rec_cap;
    uint64_t offset;
    uint64_t skipped;
    int truncated;
    int failed;
    char err[256];
};

static uint16_t r16(const pcap_reader_t *r, const unsigned char *p)
{
    return r->big_endian ? rd_be16(p) : rd_le16(p);
}
static uint32_t r32(const pcap_reader_t *r, const unsigned char *p)
{
    return r->big_endian ? rd_be32(p) : rd_le32(p);
}

static int fail(pcap_reader_t *r, const char *fmt, ...) PRINTF_LIKE(2, 3);
static int fail(pcap_reader_t *r, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->err, sizeof r->err, fmt, ap);
    va_end(ap);
    r->failed = 1;
    return -1;
}

/* Reads exactly n bytes. Returns 1 ok, 0 clean EOF (no bytes), -2 short read, -1 I/O error. */
static int read_exact(pcap_reader_t *r, void *dst, size_t n)
{
    if (n == 0) return 1;
    size_t got = fread(dst, 1, n, r->fp);
    r->offset += got;
    if (got == n) return 1;
    if (ferror(r->fp)) return -1;
    return got == 0 ? 0 : -2;
}

static void rec_reserve(pcap_reader_t *r, size_t n)
{
    if (n <= r->rec_cap) return;
    size_t cap = r->rec_cap ? r->rec_cap : 65536;
    while (cap < n) cap *= 2;
    free(r->rec);
    r->rec = xmalloc(cap);
    r->rec_cap = cap;
}

static int64_t ts_to_ns(uint64_t ts, int pow2, unsigned res)
{
    if (!pow2) {
        if (res <= 9) {
            static const uint64_t mul[] = {1000000000ull, 100000000ull, 10000000ull, 1000000ull,
                                           100000ull, 10000ull, 1000ull, 100ull, 10ull, 1ull};
            uint64_t m = mul[res];
            if (ts > (uint64_t)INT64_MAX / m) return INT64_MAX;
            return (int64_t)(ts * m);
        }
        uint64_t d = 1;
        for (unsigned i = 9; i < res && i < 28; i++) d *= 10;
        if (res >= 28) return 0;
        return (int64_t)(ts / d);
    }
    if (res >= 64) return 0;
    uint64_t sec = res ? ts >> res : ts;
    uint64_t frac = res ? ts & ((1ull << res) - 1) : 0;
    if (sec > (uint64_t)INT64_MAX / 1000000000ull) return INT64_MAX;
    long double f = res ? (long double)frac * 1e9L / ldexpl(1.0L, (int)res) : 0.0L;
    return (int64_t)(sec * 1000000000ull) + (int64_t)f;
}

/* ---------------------------------------------------------------- classic */

static int classic_open(pcap_reader_t *r, const unsigned char *hdr)
{
    uint32_t magic_le = rd_le32(hdr);
    switch (magic_le) {
    case 0xA1B2C3D4u: r->big_endian = 0; r->nsec = 0; break;
    case 0xA1B23C4Du: r->big_endian = 0; r->nsec = 1; break;
    case 0xD4C3B2A1u: r->big_endian = 1; r->nsec = 0; break;
    case 0x4D3CB2A1u: r->big_endian = 1; r->nsec = 1; break;
    default: return fail(r, "unrecognised file magic 0x%08x (not pcap/pcapng)", magic_le);
    }
    uint16_t vmaj = r16(r, hdr + 4);
    uint16_t vmin = r16(r, hdr + 6);
    if (vmaj != 2) return fail(r, "unsupported pcap version %u.%u", vmaj, vmin);
    r->snaplen = r32(r, hdr + 16);
    r->linktype = r32(r, hdr + 20) & 0x0000FFFFu; /* upper bits carry FCS info */
    r->fmt = PCAP_FMT_CLASSIC;
    return 0;
}

static int classic_next(pcap_reader_t *r, pcap_packet_t *pkt)
{
    unsigned char h[16];
    int rc = read_exact(r, h, sizeof h);
    if (rc == 0) return 0;
    if (rc == -2) { r->truncated = 1; return 0; }
    if (rc < 0) return fail(r, "read error: %s", strerror(errno));

    uint32_t sec = r32(r, h), frac = r32(r, h + 4);
    uint32_t incl = r32(r, h + 8), orig = r32(r, h + 12);
    if (incl > MAX_RECORD_LEN)
        return fail(r, "corrupt record header at offset %llu: captured length %u exceeds limit",
                    (unsigned long long)(r->offset - 16), incl);
    if (r->nsec ? frac >= 1000000000u : frac >= 1000000u) {
        /* Tolerated: some writers emit sloppy fractions. Clamp. */
        frac = r->nsec ? 999999999u : 999999u;
    }
    rec_reserve(r, incl);
    rc = read_exact(r, r->rec, incl);
    if (rc == 0 || rc == -2) { r->truncated = 1; return 0; }
    if (rc < 0) return fail(r, "read error: %s", strerror(errno));

    pkt->ts_ns = (int64_t)sec * 1000000000LL + (r->nsec ? (int64_t)frac : (int64_t)frac * 1000LL);
    pkt->caplen = incl;
    pkt->origlen = orig < incl ? incl : orig;
    pkt->linktype = r->linktype;
    pkt->data = r->rec;
    return 1;
}

/* ----------------------------------------------------------------- pcapng */

/* Parses an Interface Description Block body. */
static int ng_parse_idb(pcap_reader_t *r, const unsigned char *body, size_t blen)
{
    if (blen < 8) { r->skipped++; return 0; }
    if (r->n_ifaces >= MAX_INTERFACES) return fail(r, "too many pcapng interfaces");
    iface_t ifc = {0};
    ifc.linktype = r16(r, body);
    ifc.snaplen = r32(r, body + 4);
    ifc.tsres = 6;
    ifc.tsres_pow2 = 0;
    size_t o = 8;
    while (o + 4 <= blen) {
        uint16_t code = r16(r, body + o), olen = r16(r, body + o + 2);
        o += 4;
        if (code == 0) break;
        if (olen > blen - o) break;
        if (code == 9 && olen >= 1) {
            unsigned char v = body[o];
            ifc.tsres_pow2 = (v & 0x80) != 0;
            ifc.tsres = v & 0x7F;
        } else if (code == 14 && olen >= 8) {
            uint64_t hi = r32(r, body + o), lo = r32(r, body + o + 4);
            uint64_t v = r->big_endian ? (hi << 32) | lo : (lo << 32) | hi;
            ifc.tsoffset = (int64_t)v;
        }
        o += ((size_t)olen + 3u) & ~(size_t)3u;
    }
    r->ifaces = xreallocarray(r->ifaces, r->n_ifaces + 1, sizeof *r->ifaces);
    r->ifaces[r->n_ifaces++] = ifc;
    return 0;
}

static int ng_set_byte_order(pcap_reader_t *r, const unsigned char *bom)
{
    if (rd_le32(bom) == BYTE_ORDER_MAGIC) r->big_endian = 0;
    else if (rd_be32(bom) == BYTE_ORDER_MAGIC) r->big_endian = 1;
    else return fail(r, "pcapng section header has invalid byte-order magic");
    return 0;
}

static int ng_next(pcap_reader_t *r, pcap_packet_t *pkt)
{
    for (;;) {
        unsigned char h[8];
        int rc = read_exact(r, h, sizeof h);
        if (rc == 0) return 0;
        if (rc == -2) { r->truncated = 1; return 0; }
        if (rc < 0) return fail(r, "read error: %s", strerror(errno));

        uint32_t type = rd_le32(h); /* SHB type is a palindrome, others need order */
        if (type == BT_SHB) {
            /* New section: byte order may change; read BOM first. */
            unsigned char bom[4];
            rc = read_exact(r, bom, 4);
            if (rc != 1) { if (rc < 0) return fail(r, "read error"); r->truncated = 1; return 0; }
            if (ng_set_byte_order(r, bom) < 0) return -1;
            uint32_t len = r32(r, h + 4);
            if (len < 28 || len % 4 || len > MAX_RECORD_LEN)
                return fail(r, "corrupt pcapng section header (length %u)", len);
            rec_reserve(r, len);
            rc = read_exact(r, r->rec, len - 12);
            if (rc != 1) { if (rc < 0) return fail(r, "read error"); r->truncated = 1; return 0; }
            uint32_t trailer = r32(r, r->rec + len - 16);
            if (trailer != len) return fail(r, "pcapng section header length mismatch");
            uint16_t vmaj = r16(r, r->rec);
            if (vmaj != 1) return fail(r, "unsupported pcapng major version %u", vmaj);
            free(r->ifaces);
            r->ifaces = NULL;
            r->n_ifaces = 0;
            continue;
        }
        type = r32(r, h);
        uint32_t len = r32(r, h + 4);
        if (len < 12 || len % 4 || len > MAX_RECORD_LEN)
            return fail(r, "corrupt pcapng block at offset %llu (type 0x%08x, length %u)",
                        (unsigned long long)(r->offset - 8), type, len);
        size_t rest = len - 8; /* body + trailing length */
        rec_reserve(r, rest);
        rc = read_exact(r, r->rec, rest);
        if (rc == 0 || rc == -2) { r->truncated = 1; return 0; }
        if (rc < 0) return fail(r, "read error: %s", strerror(errno));
        if (r32(r, r->rec + rest - 4) != len)
            return fail(r, "pcapng block length mismatch at offset %llu",
                        (unsigned long long)(r->offset - len));
        const unsigned char *b = r->rec;
        size_t blen = rest - 4;

        if (type == BT_IDB) {
            if (ng_parse_idb(r, b, blen) < 0) return -1;
            continue;
        }
        uint32_t ifid, caplen, origlen;
        uint64_t ts;
        const unsigned char *data;
        size_t avail;
        if (type == BT_EPB) {
            if (blen < 20) { r->skipped++; continue; }
            ifid = r32(r, b);
            ts = ((uint64_t)r32(r, b + 4) << 32) | r32(r, b + 8);
            caplen = r32(r, b + 12);
            origlen = r32(r, b + 16);
            data = b + 20;
            avail = blen - 20;
        } else if (type == BT_PB) {
            if (blen < 20) { r->skipped++; continue; }
            ifid = r16(r, b);
            ts = ((uint64_t)r32(r, b + 4) << 32) | r32(r, b + 8);
            caplen = r32(r, b + 12);
            origlen = r32(r, b + 16);
            data = b + 20;
            avail = blen - 20;
        } else if (type == BT_SPB) {
            if (blen < 4 || r->n_ifaces == 0) { r->skipped++; continue; }
            ifid = 0;
            ts = 0;
            origlen = r32(r, b);
            data = b + 4;
            avail = blen - 4;
            caplen = origlen;
            if (r->ifaces[0].snaplen && caplen > r->ifaces[0].snaplen) caplen = r->ifaces[0].snaplen;
            if (caplen > avail) caplen = (uint32_t)avail;
        } else {
            continue; /* NRB, ISB, DSB, custom... not needed for statistics */
        }
        if (ifid >= r->n_ifaces || caplen > avail) { r->skipped++; continue; }
        const iface_t *ifc = &r->ifaces[ifid];
        int64_t ns = (type == BT_SPB) ? 0 : ts_to_ns(ts, ifc->tsres_pow2, ifc->tsres);
        if (ifc->tsoffset > -4000000000LL && ifc->tsoffset < 4000000000LL) {
            int64_t off = ifc->tsoffset * 1000000000LL, sum;
            if (!__builtin_add_overflow(ns, off, &sum)) ns = sum;
        }
        pkt->ts_ns = ns;
        pkt->caplen = caplen;
        pkt->origlen = origlen < caplen ? caplen : origlen;
        pkt->linktype = ifc->linktype;
        pkt->data = data;
        return 1;
    }
}

/* ------------------------------------------------------------------ public */

pcap_reader_t *pcap_reader_open(const char *path, char *err, size_t errlen)
{
    pcap_reader_t *r = xcalloc(1, sizeof *r);
    if (strcmp(path, "-") == 0) {
        r->fp = stdin;
        r->is_stdin = 1;
    } else {
        struct stat st;
        if (stat(path, &st) != 0) {
            snprintf(err, errlen, "%s", strerror(errno));
            free(r);
            return NULL;
        }
        if (S_ISDIR(st.st_mode)) {
            snprintf(err, errlen, "is a directory");
            free(r);
            return NULL;
        }
        r->fp = fopen(path, "rb");
        if (!r->fp) {
            snprintf(err, errlen, "%s", strerror(errno));
            free(r);
            return NULL;
        }
    }
    if (!r->is_stdin) {
        /* Large stdio buffer: we read sequentially, never seek. Must precede any I/O. */
        r->iobuf = xmalloc(IO_BUFFER_SIZE);
        setvbuf(r->fp, r->iobuf, _IOFBF, IO_BUFFER_SIZE);
    }

    unsigned char hdr[24];
    int rc = read_exact(r, hdr, 4);
    if (rc != 1) {
        snprintf(err, errlen, rc == 0 ? "file is empty" : "file too short for a capture header");
        pcap_reader_close(r);
        return NULL;
    }
    if (rd_le32(hdr) == BT_SHB) {
        /* pcapng: re-use ng_next() machinery by handling the first SHB here. */
        unsigned char rest[8];
        if (read_exact(r, rest, 8) != 1) {
            snprintf(err, errlen, "truncated pcapng section header");
            pcap_reader_close(r);
            return NULL;
        }
        if (ng_set_byte_order(r, rest + 4) < 0) {
            snprintf(err, errlen, "%s", r->err);
            pcap_reader_close(r);
            return NULL;
        }
        uint32_t len = r32(r, rest);
        if (len < 28 || len % 4 || len > MAX_RECORD_LEN) {
            snprintf(err, errlen, "corrupt pcapng section header (length %u)", len);
            pcap_reader_close(r);
            return NULL;
        }
        rec_reserve(r, len);
        if (read_exact(r, r->rec, len - 12) != 1 || r32(r, r->rec + len - 16) != len) {
            snprintf(err, errlen, "truncated or inconsistent pcapng section header");
            pcap_reader_close(r);
            return NULL;
        }
        if (r16(r, r->rec) != 1) {
            snprintf(err, errlen, "unsupported pcapng major version %u", r16(r, r->rec));
            pcap_reader_close(r);
            return NULL;
        }
        r->fmt = PCAP_FMT_NG;
        return r;
    }
    rc = read_exact(r, hdr + 4, 20);
    if (rc != 1) {
        snprintf(err, errlen, "file too short for a pcap global header");
        pcap_reader_close(r);
        return NULL;
    }
    if (classic_open(r, hdr) < 0) {
        snprintf(err, errlen, "%s", r->err);
        pcap_reader_close(r);
        return NULL;
    }
    return r;
}

int pcap_reader_next(pcap_reader_t *r, pcap_packet_t *pkt)
{
    if (r->failed) return -1;
    if (r->truncated) return 0;
    return r->fmt == PCAP_FMT_NG ? ng_next(r, pkt) : classic_next(r, pkt);
}

const char *pcap_reader_error(const pcap_reader_t *r) { return r->err[0] ? r->err : "unknown error"; }
int pcap_reader_truncated(const pcap_reader_t *r) { return r->truncated; }
pcap_format_t pcap_reader_format(const pcap_reader_t *r) { return r->fmt; }
uint64_t pcap_reader_skipped(const pcap_reader_t *r) { return r->skipped; }
uint64_t pcap_reader_offset(const pcap_reader_t *r) { return r->offset; }

void pcap_reader_close(pcap_reader_t *r)
{
    if (!r) return;
    if (r->fp && !r->is_stdin) fclose(r->fp);
    free(r->iobuf);
    free(r->ifaces);
    free(r->rec);
    free(r);
}
