#ifndef PCAPREPORT_PCAP_READER_H
#define PCAPREPORT_PCAP_READER_H

#include <stddef.h>
#include <stdint.h>

/*
 * Streaming reader for classic libpcap files (both byte orders, micro- and
 * nanosecond variants) and pcapng (SHB/IDB/EPB/SPB/obsolete PB, multiple
 * sections, per-interface timestamp resolution and offset).
 *
 * Only one record is kept in memory at a time; the returned data pointer is
 * valid until the next call to pcap_reader_next() or pcap_reader_close().
 */

typedef enum { PCAP_FMT_CLASSIC = 1, PCAP_FMT_NG = 2 } pcap_format_t;

typedef struct {
    int64_t ts_ns;              /* timestamp, ns since Unix epoch          */
    uint32_t caplen;            /* bytes available in data                 */
    uint32_t origlen;           /* original length on the wire             */
    uint32_t linktype;          /* LINKTYPE_* of the capturing interface   */
    const unsigned char *data;
} pcap_packet_t;

typedef struct pcap_reader pcap_reader_t;

/* Opens path ("-" = stdin). On failure returns NULL and writes reason to err. */
pcap_reader_t *pcap_reader_open(const char *path, char *err, size_t errlen);

/*
 * Returns 1 when a packet was produced, 0 at clean end of file, -1 on a
 * fatal format error (see pcap_reader_error()). A file cut in the middle of a
 * record yields 0 and pcap_reader_truncated() becomes non-zero.
 */
int pcap_reader_next(pcap_reader_t *r, pcap_packet_t *pkt);

const char *pcap_reader_error(const pcap_reader_t *r);
int pcap_reader_truncated(const pcap_reader_t *r);
pcap_format_t pcap_reader_format(const pcap_reader_t *r);
/* Records skipped because they were inconsistent but recoverable (pcapng). */
uint64_t pcap_reader_skipped(const pcap_reader_t *r);
/* Bytes consumed so far (for progress / diagnostics). */
uint64_t pcap_reader_offset(const pcap_reader_t *r);
void pcap_reader_close(pcap_reader_t *r);

#endif
