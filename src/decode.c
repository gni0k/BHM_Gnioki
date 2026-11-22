#define _POSIX_C_SOURCE 200809L
#include "decode.h"
#include "util.h"

#include <arpa/inet.h>
#include <string.h>

#define ETH_IPV4   0x0800
#define ETH_ARP    0x0806
#define ETH_VLAN   0x8100
#define ETH_QINQ   0x88A8
#define ETH_QINQ2  0x9100
#define ETH_IPV6   0x86DD
#define ETH_PPPOES 0x8864
#define ETH_MPLS   0x8847
#define ETH_MPLSM  0x8848

typedef enum { NEXT_NONE, NEXT_IPV4, NEXT_IPV6, NEXT_GUESS } l3_kind_t;

const char *linktype_name(uint32_t lt)
{
    switch (lt) {
    case LINKTYPE_NULL: return "BSD loopback (NULL)";
    case LINKTYPE_ETHERNET: return "Ethernet";
    case LINKTYPE_RAW_BSD:
    case LINKTYPE_RAW_BSD2:
    case LINKTYPE_RAW: return "Raw IP";
    case LINKTYPE_LOOP: return "OpenBSD loopback";
    case LINKTYPE_LINUX_SLL: return "Linux cooked (SLL)";
    case LINKTYPE_IPV4: return "Raw IPv4";
    case LINKTYPE_IPV6: return "Raw IPv6";
    case LINKTYPE_LINUX_SLL2: return "Linux cooked v2 (SLL2)";
    default: return "unsupported";
    }
}

static l3_kind_t ethertype_kind(uint16_t et)
{
    if (et == ETH_IPV4) return NEXT_IPV4;
    if (et == ETH_IPV6) return NEXT_IPV6;
    return NEXT_NONE;
}

/* Skips VLAN tags, PPPoE and MPLS. *off points to ethertype field position. */
static l3_kind_t ether_payload(const unsigned char *d, size_t len, size_t *off, unsigned *err)
{
    size_t o = *off;
    if (o + 2 > len) { *err |= PERR_TRUNC_L2; return NEXT_NONE; }
    uint16_t et = rd_be16(d + o);
    o += 2;
    for (int depth = 0; depth < 8 && (et == ETH_VLAN || et == ETH_QINQ || et == ETH_QINQ2); depth++) {
        if (o + 4 > len) { *err |= PERR_TRUNC_L2; return NEXT_NONE; }
        et = rd_be16(d + o + 2);
        o += 4;
    }
    if (et == ETH_PPPOES) {
        if (o + 8 > len) { *err |= PERR_TRUNC_L2; return NEXT_NONE; }
        uint16_t ppp = rd_be16(d + o + 6);
        o += 8;
        *off = o;
        if (ppp == 0x0021) return NEXT_IPV4;
        if (ppp == 0x0057) return NEXT_IPV6;
        return NEXT_NONE;
    }
    if (et == ETH_MPLS || et == ETH_MPLSM) {
        for (int i = 0; i < 16; i++) {
            if (o + 4 > len) { *err |= PERR_TRUNC_L2; return NEXT_NONE; }
            int bos = (d[o + 2] & 0x01) != 0;
            o += 4;
            if (bos) { *off = o; return NEXT_GUESS; }
        }
        *err |= PERR_TRUNC_L2;
        return NEXT_NONE;
    }
    *off = o;
    return ethertype_kind(et);
}

static uint32_t csum_add(uint32_t sum, const unsigned char *p, size_t n)
{
    while (n > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; n -= 2; }
    if (n) sum += (uint32_t)(p[0] << 8);
    return sum;
}
static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void set_v4(ip_addr_t *a, const unsigned char *p)
{
    memset(a, 0, sizeof *a);
    a->family = 4;
    a->a[10] = 0xFF;
    a->a[11] = 0xFF;
    memcpy(a->a + 12, p, 4);
}
static void set_v6(ip_addr_t *a, const unsigned char *p)
{
    a->family = 6;
    memcpy(a->a, p, 16);
}

/* L4 parsing. seg points at transport header, seglen = bytes per IP header,
 * avail = bytes actually captured from seg. pseudo = pseudo-header sum. */
static void decode_l4(pkt_info_t *pi, const unsigned char *seg, size_t seglen, size_t avail,
                      uint32_t pseudo, int verify)
{
    if (pi->proto == PROTO_TCP) {
        if (avail < 20) { pi->err |= PERR_TRUNC_L4; return; }
        if (seglen < 20) { pi->err |= PERR_BAD_IPLEN; return; }
        unsigned doff = (unsigned)(seg[12] >> 4) * 4u;
        if (doff < 20 || doff > seglen) { pi->err |= PERR_BAD_TCPOFF; return; }
        pi->sport = rd_be16(seg);
        pi->dport = rd_be16(seg + 2);
        pi->seq = rd_be32(seg + 4);
        pi->ack = rd_be32(seg + 8);
        pi->tcp_flags = seg[13];
        pi->window = rd_be16(seg + 14);
        pi->payload_len = (uint32_t)(seglen - doff);
        pi->has_l4 = 1;
        if (verify && avail >= seglen) {
            uint32_t s = csum_add(pseudo, seg, seglen);
            pi->l4_csum_ok = csum_fold(s) == 0;
            if (!pi->l4_csum_ok) pi->err |= PERR_BAD_L4CSUM;
        }
    } else if (pi->proto == PROTO_UDP) {
        if (avail < 8) { pi->err |= PERR_TRUNC_L4; return; }
        if (seglen < 8) { pi->err |= PERR_BAD_IPLEN; return; }
        uint16_t ulen = rd_be16(seg + 4);
        /* ulen==0 is legal for IPv6 jumbograms only; treat as "use IP length". */
        if (ulen != 0 && (ulen < 8 || ulen > seglen)) { pi->err |= PERR_BAD_UDPLEN; return; }
        if (ulen == 0) ulen = (uint16_t)MIN(seglen, 0xFFFFu);
        pi->sport = rd_be16(seg);
        pi->dport = rd_be16(seg + 2);
        pi->payload_len = (uint32_t)ulen - 8u;
        pi->has_l4 = 1;
        uint16_t c = rd_be16(seg + 6);
        if (verify && avail >= ulen && !(c == 0 && pi->ipver == 4)) {
            uint32_t s = csum_add(pseudo, seg, ulen);
            pi->l4_csum_ok = csum_fold(s) == 0;
            if (!pi->l4_csum_ok) pi->err |= PERR_BAD_L4CSUM;
        }
    }
}

static decode_status_t decode_ipv4(pkt_info_t *pi, const unsigned char *p, size_t avail, int verify)
{
    if (avail < 20) { pi->err |= PERR_TRUNC_L3; return DEC_MALFORMED; }
    if ((p[0] >> 4) != 4) { pi->err |= PERR_BAD_IPHDR; return DEC_MALFORMED; }
    size_t ihl = (size_t)(p[0] & 0x0F) * 4u;
    if (ihl < 20) { pi->err |= PERR_BAD_IPHDR; return DEC_MALFORMED; }
    if (avail < ihl) { pi->err |= PERR_TRUNC_L3; return DEC_MALFORMED; }
    size_t tot = rd_be16(p + 2);
    pi->ipver = 4;
    pi->ttl = p[8];
    pi->proto = p[9];
    set_v4(&pi->src, p + 12);
    set_v4(&pi->dst, p + 16);
    if (tot < ihl) { pi->err |= PERR_BAD_IPLEN; return DEC_MALFORMED; }
    if (tot > avail && !pi->snap_truncated) {
        /* frame physically shorter than the IP header claims */
        pi->err |= PERR_BAD_IPLEN;
        return DEC_MALFORMED;
    }
    pi->ip_len = (uint32_t)tot;
    if (verify) {
        pi->ip_csum_ok = csum_fold(csum_add(0, p, ihl)) == 0;
        if (!pi->ip_csum_ok) pi->err |= PERR_BAD_IPCSUM;
    }
    uint16_t frag = rd_be16(p + 6);
    int mf = (frag & 0x2000) != 0;
    unsigned foff = frag & 0x1FFFu;
    pi->is_fragment = mf || foff;
    if (foff) return DEC_OK; /* no transport header in non-first fragment */
    size_t seglen = tot - ihl;
    size_t savail = MIN(avail, tot) - ihl;
    uint32_t pseudo = csum_add(0, p + 12, 8) + pi->proto + (uint32_t)seglen;
    if (mf) verify = 0; /* checksum covers whole datagram */
    decode_l4(pi, p + ihl, seglen, savail, pseudo, verify);
    return (pi->err & (PERR_TRUNC_L4 | PERR_BAD_TCPOFF | PERR_BAD_UDPLEN | PERR_BAD_IPLEN))
               ? DEC_MALFORMED : DEC_OK;
}

static decode_status_t decode_ipv6(pkt_info_t *pi, const unsigned char *p, size_t avail, int verify)
{
    if (avail < 40) { pi->err |= PERR_TRUNC_L3; return DEC_MALFORMED; }
    if ((p[0] >> 4) != 6) { pi->err |= PERR_BAD_IPHDR; return DEC_MALFORMED; }
    size_t plen = rd_be16(p + 4);
    pi->ipver = 6;
    pi->ttl = p[7];
    set_v6(&pi->src, p + 8);
    set_v6(&pi->dst, p + 24);
    if (plen == 0) plen = avail - 40; /* jumbogram (hop-by-hop option) - best effort */
    size_t tot = 40 + plen;
    if (tot > avail && !pi->snap_truncated) { pi->err |= PERR_BAD_IPLEN; return DEC_MALFORMED; }
    pi->ip_len = (uint32_t)MIN(tot, 0xFFFFFFFFu);
    size_t lim = MIN(avail, tot);
    uint8_t nh = p[6];
    size_t o = 40;
    for (int guard = 0; guard < 16; guard++) {
        if (nh == 0 || nh == 43 || nh == 60 || nh == 51 || nh == 44) {
            if (o + 8 > lim) {
                pi->proto = nh;
                pi->err |= (o + 8 > tot) ? PERR_BAD_EXTHDR : PERR_TRUNC_L3;
                return DEC_MALFORMED;
            }
            uint8_t next = p[o];
            size_t hl;
            if (nh == 44) {
                uint16_t fo = rd_be16(p + o + 2);
                pi->is_fragment = 1;
                hl = 8;
                if ((fo & 0xFFF8u) != 0) { pi->proto = next; return DEC_OK; }
                verify = 0;
            } else if (nh == 51) {
                hl = ((size_t)p[o + 1] + 2u) * 4u;
            } else {
                hl = ((size_t)p[o + 1] + 1u) * 8u;
            }
            if (o + hl > tot) { pi->err |= PERR_BAD_EXTHDR; pi->proto = nh; return DEC_MALFORMED; }
            o += hl;
            nh = next;
            continue;
        }
        break;
    }
    pi->proto = nh;
    if (o > tot) { pi->err |= PERR_BAD_EXTHDR; return DEC_MALFORMED; }
    size_t seglen = tot - o;
    size_t savail = lim > o ? lim - o : 0;
    uint32_t pseudo = csum_add(0, p + 8, 32) + (uint32_t)(seglen >> 16) + (uint32_t)(seglen & 0xFFFF) + nh;
    decode_l4(pi, p + o, seglen, savail, pseudo, verify);
    return (pi->err & (PERR_TRUNC_L4 | PERR_BAD_TCPOFF | PERR_BAD_UDPLEN | PERR_BAD_IPLEN))
               ? DEC_MALFORMED : DEC_OK;
}

decode_status_t decode_packet(const pcap_packet_t *pkt, int verify, pkt_info_t *pi)
{
    memset(pi, 0, sizeof *pi);
    pi->ts_ns = pkt->ts_ns;
    pi->wirelen = pkt->origlen;
    pi->caplen = pkt->caplen;
    pi->snap_truncated = pkt->caplen < pkt->origlen;
    pi->ip_csum_ok = -1;
    pi->l4_csum_ok = -1;

    const unsigned char *d = pkt->data;
    size_t len = pkt->caplen;
    size_t off = 0;
    l3_kind_t k = NEXT_NONE;

    switch (pkt->linktype) {
    case LINKTYPE_ETHERNET:
        if (len < 14) { pi->err |= PERR_TRUNC_L2; return DEC_MALFORMED; }
        off = 12;
        if (rd_be16(d + 12) < 0x0600) return DEC_NON_IP; /* 802.3 length + LLC */
        k = ether_payload(d, len, &off, &pi->err);
        break;
    case LINKTYPE_NULL:
    case LINKTYPE_LOOP: {
        if (len < 4) { pi->err |= PERR_TRUNC_L2; return DEC_MALFORMED; }
        uint32_t fam = pkt->linktype == LINKTYPE_LOOP ? rd_be32(d) : rd_le32(d);
        if (pkt->linktype == LINKTYPE_NULL && (fam & 0xFFFF0000u)) fam = rd_be32(d);
        off = 4;
        if (fam == 2) k = NEXT_IPV4;
        else if (fam == 10 || fam == 24 || fam == 28 || fam == 30) k = NEXT_IPV6;
        break;
    }
    case LINKTYPE_RAW:
    case LINKTYPE_RAW_BSD:
    case LINKTYPE_RAW_BSD2:
        k = NEXT_GUESS;
        break;
    case LINKTYPE_IPV4: k = NEXT_IPV4; break;
    case LINKTYPE_IPV6: k = NEXT_IPV6; break;
    case LINKTYPE_LINUX_SLL:
        if (len < 16) { pi->err |= PERR_TRUNC_L2; return DEC_MALFORMED; }
        off = 14;
        k = ether_payload(d, len, &off, &pi->err);
        break;
    case LINKTYPE_LINUX_SLL2:
        if (len < 20) { pi->err |= PERR_TRUNC_L2; return DEC_MALFORMED; }
        k = ethertype_kind(rd_be16(d)); /* protocol type is the first field */
        off = 20;
        break;
    default:
        return DEC_UNSUPPORTED_LINK;
    }
    if (pi->err) return DEC_MALFORMED;
    if (k == NEXT_GUESS) {
        if (off >= len) { pi->err |= PERR_TRUNC_L3; return DEC_MALFORMED; }
        unsigned v = d[off] >> 4;
        k = v == 4 ? NEXT_IPV4 : v == 6 ? NEXT_IPV6 : NEXT_NONE;
        if (k == NEXT_NONE) return DEC_NON_IP;
    }
    if (k == NEXT_NONE) return DEC_NON_IP;
    if (off > len) { pi->err |= PERR_TRUNC_L2; return DEC_MALFORMED; }
    /* If frame was cut by snaplen, IP lengths may legitimately exceed caplen. */
    if (k == NEXT_IPV4) return decode_ipv4(pi, d + off, len - off, verify);
    return decode_ipv6(pi, d + off, len - off, verify);
}

const char *ip_to_str(const ip_addr_t *a, char *buf, size_t n)
{
    const char *r = a->family == 4 ? inet_ntop(AF_INET, a->a + 12, buf, (socklen_t)n)
                                   : inet_ntop(AF_INET6, a->a, buf, (socklen_t)n);
    if (!r && n) snprintf(buf, n, "?");
    return buf;
}

int ip_cmp(const ip_addr_t *a, const ip_addr_t *b)
{
    if (a->family != b->family) return a->family < b->family ? -1 : 1;
    return memcmp(a->a, b->a, 16);
}

int ip_is_multicast_or_broadcast(const ip_addr_t *a)
{
    if (a->family == 4) {
        const uint8_t *v = a->a + 12;
        if (v[0] >= 224 && v[0] <= 239) return 1;
        if (v[0] == 255 && v[1] == 255 && v[2] == 255 && v[3] == 255) return 1;
        return 0;
    }
    return a->a[0] == 0xFF;
}
