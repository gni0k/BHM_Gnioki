#ifndef PCAPREPORT_UTIL_H
#define PCAPREPORT_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#if defined(__GNUC__)
#define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#else
#define PRINTF_LIKE(f, a)
#endif

/* Verbosity: 0 = errors only, 1 = normal, 2 = verbose. */
extern int g_verbosity;

void log_error(const char *fmt, ...) PRINTF_LIKE(1, 2);
void log_warn(const char *fmt, ...) PRINTF_LIKE(1, 2);
void log_info(const char *fmt, ...) PRINTF_LIKE(1, 2);
void log_debug(const char *fmt, ...) PRINTF_LIKE(1, 2);

/* Allocation wrappers: abort with a message on OOM (no sane recovery possible). */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
/* Overflow-checked n*sz realloc. */
void *xreallocarray(void *p, size_t n, size_t sz);
char *xstrdup(const char *s);

/* Growable byte buffer. */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_reserve(buf_t *b, size_t extra);
void buf_append(buf_t *b, const void *p, size_t n);
void buf_append_str(buf_t *b, const char *s);
void buf_printf(buf_t *b, const char *fmt, ...) PRINTF_LIKE(2, 3);

/* Unaligned big/little endian loads (safe for any alignment). */
static inline uint16_t rd_be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint16_t rd_le16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void wr_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

/* Human readable formatting into caller buffer; returns buf. */
char *fmt_bytes(char *buf, size_t n, double bytes);       /* 1.23 MB   */
char *fmt_count(char *buf, size_t n, uint64_t v);         /* 1 234 567 */
char *fmt_rate_bits(char *buf, size_t n, double bps);     /* 12.3 Mbit/s */
char *fmt_duration(char *buf, size_t n, double seconds);  /* 1h 02m 03s */
char *fmt_si(char *buf, size_t n, double v);              /* 1.2k, 3.4M */
char *fmt_time_utc(char *buf, size_t n, int64_t ns);      /* 2024-01-01 12:00:00.123 UTC */

/* Create directory (and parents). Returns 0 on success, -1 with errno set. */
int mkdir_p(const char *path);
/* Join directory and file name into newly allocated string. */
char *path_join(const char *dir, const char *name);

#endif
