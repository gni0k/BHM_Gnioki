#ifndef PCAPREPORT_DECODE_H
#define PCAPREPORT_DECODE_H

#include <stddef.h>
#include <stdint.h>
#include "pcap_reader.h"

/* Link-layer types we understand (values from the tcpdump.org LINKTYPE registry). */
#define LINKTYPE_NULL        0
#define LINKTYPE_ETHERNET    1
#define LINKTYPE_RAW_BSD     12
#define LINKTYPE_RAW_BSD2    14
#define LINKTYPE_RAW         101
#define LINKTYPE_LOOP        108
#define LINKTYPE_LINUX_SLL   113
#define LINKTYPE_IPV4        228
#define LINKTYPE_IPV6        229
#define LINKTYPE_LINUX_SLL2  276

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/* An IPv4 address is stored as IPv4-mapped IPv6 (::ffff:a.b.c.d) with family=4. */
typedef struct {
    uint8_t family;  /* 4 or 6 */
    uint8_t a[16];
} ip_addr_t;

typedef enum {
    DEC_OK = 0,           /* L3 decoded (L4 may still be absent, see has_l4) */
    DEC_UNSUPPORTED_LINK, /* link type not supported */
    DEC_NON_IP,           /* valid frame, but not IPv4/IPv6 (ARP, LLDP...) */
    DEC_MALFORMED         /* headers inconsistent or cut; see err */
} decode_status_t;

/* Malformation bits (pkt_info_t.err). */
#define PERR_TRUNC_L2     0x0001u /* frame shorter than link header           */
#define PERR_TRUNC_L3     0x0002u /* IP header cut by snaplen / frame end     */
#define PERR_BAD_IPHDR    0x0004u /* bad version / IHL                        */
#define PERR_BAD_IPLEN    0x0008u /* IP total length inconsistent             */
#define PERR_TRUNC_L4     0x0010u /* TCP/UDP header cut                       */
#define PERR_BAD_TCPOFF   0x0020u /* TCP data offset < 5 or beyond segment    */
#define PERR_BAD_UDPLEN   0x0040u /* UDP length field inconsistent            */
#define PERR_BAD_IPCSUM   0x0080u /* IPv4 header checksum mismatch            */
#define PERR_BAD_L4CSUM   0x0100u /* TCP/UDP checksum mismatch                */
#define PERR_BAD_EXTHDR   0x0200u /* IPv6 extension header chain broken       */

#define PROTO_ICMP   1
#define PROTO_TCP    6
#define PROTO_UDP    17
#define PROTO_ICMPV6 58

typedef struct {
    int64_t ts_ns;
    uint32_t wirelen;       /* original frame length                */
    uint32_t caplen;
    int snap_truncated;     /* caplen < wirelen                     */
    uint8_t ipver;          /* 4, 6 or 0                            */
    uint8_t proto;          /* final transport protocol number      */
    uint8_t ttl;            /* TTL / hop limit                      */
    ip_addr_t src, dst;
    uint32_t ip_len;        /* IP packet length (header + payload)  */
    int is_fragment;        /* part of a fragmented datagram        */
    int has_l4;             /* sport/dport/tcp fields are valid     */
    uint16_t sport, dport;
    /* TCP */
    uint8_t tcp_flags;
    uint32_t seq, ack;
    uint16_t window;
    uint32_t payload_len;   /* L4 payload bytes (per IP length)     */
    /* checksum verification results: -1 not checked, 0 bad, 1 good */
    int ip_csum_ok;
    int l4_csum_ok;
    unsigned err;           /* PERR_* bits                          */
} pkt_info_t;

decode_status_t decode_packet(const pcap_packet_t *pkt, int verify_checksums, pkt_info_t *out);

/* Formats address (inet_ntop), buffer must be >= 46 bytes. */
const char *ip_to_str(const ip_addr_t *a, char *buf, size_t n);
int ip_cmp(const ip_addr_t *a, const ip_addr_t *b);
int ip_is_multicast_or_broadcast(const ip_addr_t *a);
const char *linktype_name(uint32_t lt);

#endif
