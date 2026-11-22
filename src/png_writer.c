#include "png_writer.h"
#include "util.h"
#include "zcompat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void chunk(buf_t *out, const char *type, const unsigned char *data, size_t n)
{
    unsigned char len[4], crc[4];
    wr_be32(len, (uint32_t)n);
    buf_append(out, len, 4);
    size_t start = out->len;
    buf_append(out, type, 4);
    buf_append(out, data, n);
    wr_be32(crc, z_crc32(0, out->data + start, n + 4));
    buf_append(out, crc, 4);
}

int png_write(const canvas_t *c, const char *path)
{
    static const unsigned char sig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    buf_t png, z;
    buf_init(&png);
    buf_init(&z);
    buf_append(&png, sig, 8);

    unsigned char ihdr[13];
    wr_be32(ihdr, (uint32_t)c->w);
    wr_be32(ihdr + 4, (uint32_t)c->h);
    ihdr[8] = 8;  /* bit depth */
    ihdr[9] = 2;  /* colour type: truecolour */
    ihdr[10] = 0; /* deflate */
    ihdr[11] = 0; /* adaptive filtering */
    ihdr[12] = 0; /* no interlace */
    chunk(&png, "IHDR", ihdr, sizeof ihdr);

    /* Filter type 1 (Sub) per scanline: flat chart areas become runs of zeros. */
    size_t stride = (size_t)c->w * 3u;
    unsigned char *raw = xmalloc((stride + 1) * (size_t)c->h);
    for (int y = 0; y < c->h; y++) {
        unsigned char *dst = raw + (size_t)y * (stride + 1);
        const unsigned char *src = c->px + (size_t)y * stride;
        dst[0] = 1;
        for (size_t i = 0; i < stride; i++)
            dst[1 + i] = (unsigned char)(src[i] - (i >= 3 ? src[i - 3] : 0));
    }
    z_compress(raw, (stride + 1) * (size_t)c->h, &z);
    free(raw);
    chunk(&png, "IDAT", z.data, z.len);
    buf_free(&z);
    chunk(&png, "IEND", NULL, 0);

    int rc = 0;
    FILE *fp = fopen(path, "wb");
    if (!fp) rc = -1;
    else {
        if (fwrite(png.data, 1, png.len, fp) != png.len) rc = -1;
        int saved = errno;
        if (fclose(fp) != 0) rc = -1;
        else if (rc) errno = saved;
    }
    buf_free(&png);
    return rc;
}
