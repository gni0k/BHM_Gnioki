#include "zcompat.h"

#include <stdlib.h>
#include <string.h>

#ifndef NO_ZLIB
#include <zlib.h>
#endif

uint32_t z_crc32(uint32_t crc, const unsigned char *p, size_t n)
{
    static uint32_t table[256];
    static int init;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = 1;
    }
    crc = ~crc;
    for (size_t i = 0; i < n; i++) crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

#ifndef NO_ZLIB

const char *z_backend(void) { return "zlib " ZLIB_VERSION; }

void z_compress(const unsigned char *in, size_t n, buf_t *out)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit(&zs, 6) != Z_OK) {
        log_error("deflateInit failed");
        abort();
    }
    unsigned char chunk[65536];
    size_t off = 0;
    int flush;
    do {
        size_t take = n - off > (1u << 30) ? (1u << 30) : n - off;
        zs.next_in = (unsigned char *)(uintptr_t)(in + off);
        zs.avail_in = (uInt)take;
        off += take;
        flush = off == n ? Z_FINISH : Z_NO_FLUSH;
        do {
            zs.next_out = chunk;
            zs.avail_out = sizeof chunk;
            int rc = deflate(&zs, flush);
            if (rc == Z_STREAM_ERROR) { log_error("deflate failed"); abort(); }
            buf_append(out, chunk, sizeof chunk - zs.avail_out);
        } while (zs.avail_out == 0);
    } while (flush != Z_FINISH);
    deflateEnd(&zs);
}

#else /* NO_ZLIB: stored blocks */

const char *z_backend(void) { return "built-in (stored, uncompressed)"; }

void z_compress(const unsigned char *in, size_t n, buf_t *out)
{
    unsigned char hdr[2] = {0x78, 0x01}; /* CMF/FLG: deflate, 32K window, check bits ok */
    buf_append(out, hdr, 2);
    uint32_t a = 1, b = 0;
    size_t off = 0;
    do {
        size_t len = n - off > 65535 ? 65535 : n - off;
        unsigned char bh[5];
        bh[0] = (off + len == n) ? 1 : 0; /* BFINAL, BTYPE=00 */
        bh[1] = (unsigned char)(len & 0xFF);
        bh[2] = (unsigned char)(len >> 8);
        bh[3] = (unsigned char)(~len & 0xFF);
        bh[4] = (unsigned char)((~len >> 8) & 0xFF);
        buf_append(out, bh, 5);
        buf_append(out, in + off, len);
        for (size_t i = 0; i < len; i++) {
            a = (a + in[off + i]) % 65521u;
            b = (b + a) % 65521u;
        }
        off += len;
    } while (off < n);
    unsigned char ad[4];
    wr_be32(ad, (b << 16) | a);
    buf_append(out, ad, 4);
}

#endif
