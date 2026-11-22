#ifndef PCAPREPORT_ZCOMPAT_H
#define PCAPREPORT_ZCOMPAT_H

#include <stddef.h>
#include <stdint.h>
#include "util.h"

/*
 * zlib-format compression used by both the PNG and the PDF writer.
 * Built with zlib (default): real DEFLATE compression.
 * Built with NO_ZLIB=1: valid zlib stream made of *stored* (uncompressed)
 * deflate blocks - every viewer still reads it, files are just larger.
 */
void z_compress(const unsigned char *in, size_t n, buf_t *out);
uint32_t z_crc32(uint32_t crc, const unsigned char *p, size_t n);
const char *z_backend(void);

#endif
