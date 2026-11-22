#define _POSIX_C_SOURCE 200809L
#include "util.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

int g_verbosity = 1;

#if defined(__GNUC__)
__attribute__((format(printf, 2, 0)))
#endif
static void vlog(const char *prefix, const char *fmt, va_list ap)
{
    fprintf(stderr, "pcapreport: %s", prefix);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_error(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vlog("error: ", fmt, ap); va_end(ap);
}
void log_warn(const char *fmt, ...)
{
    if (g_verbosity < 1) return;
    va_list ap; va_start(ap, fmt); vlog("warning: ", fmt, ap); va_end(ap);
}
void log_info(const char *fmt, ...)
{
    if (g_verbosity < 1) return;
    va_list ap; va_start(ap, fmt); vlog("", fmt, ap); va_end(ap);
}
void log_debug(const char *fmt, ...)
{
    if (g_verbosity < 2) return;
    va_list ap; va_start(ap, fmt); vlog("debug: ", fmt, ap); va_end(ap);
}

static void oom(size_t n)
{
    fprintf(stderr, "pcapreport: fatal: out of memory (requested %zu bytes)\n", n);
    abort();
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) oom(n);
    return p;
}
void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) oom(n * sz);
    return p;
}
void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) oom(n);
    return q;
}
void *xreallocarray(void *p, size_t n, size_t sz)
{
    if (sz && n > SIZE_MAX / sz) oom(SIZE_MAX);
    return xrealloc(p, n * sz);
}
char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

void buf_init(buf_t *b) { b->data = NULL; b->len = b->cap = 0; }
void buf_free(buf_t *b) { free(b->data); buf_init(b); }
void buf_reserve(buf_t *b, size_t extra)
{
    if (extra > SIZE_MAX - b->len) oom(SIZE_MAX);
    size_t need = b->len + extra;
    if (need <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) { cap = need; break; }
        cap *= 2;
    }
    b->data = xrealloc(b->data, cap);
    b->cap = cap;
}
void buf_append(buf_t *b, const void *p, size_t n)
{
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}
void buf_append_str(buf_t *b, const char *s) { buf_append(b, s, strlen(s)); }
void buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) { buf_append(b, tmp, (size_t)n); return; }
    buf_reserve(b, (size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf((char *)b->data + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

char *fmt_bytes(char *buf, size_t n, double v)
{
    static const char *u[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    size_t i = 0;
    while (v >= 1024.0 && i + 1 < ARRAY_LEN(u)) { v /= 1024.0; i++; }
    if (i == 0) snprintf(buf, n, "%.0f %s", v, u[i]);
    else snprintf(buf, n, "%.2f %s", v, u[i]);
    return buf;
}

char *fmt_count(char *buf, size_t n, uint64_t v)
{
    char tmp[32];
    int len = snprintf(tmp, sizeof tmp, "%" PRIu64, v);
    size_t o = 0;
    for (int i = 0; i < len && o + 2 < n; i++) {
        if (i > 0 && (len - i) % 3 == 0) buf[o++] = ' ';
        buf[o++] = tmp[i];
    }
    if (n) buf[o < n ? o : n - 1] = '\0';
    return buf;
}

char *fmt_rate_bits(char *buf, size_t n, double bps)
{
    static const char *u[] = {"bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"};
    size_t i = 0;
    while (bps >= 1000.0 && i + 1 < ARRAY_LEN(u)) { bps /= 1000.0; i++; }
    snprintf(buf, n, "%.2f %s", bps, u[i]);
    return buf;
}

char *fmt_si(char *buf, size_t n, double v)
{
    static const char *u[] = {"", "k", "M", "G", "T", "P"};
    size_t i = 0;
    double a = v < 0 ? -v : v;
    while (a >= 1000.0 && i + 1 < ARRAY_LEN(u)) { a /= 1000.0; v /= 1000.0; i++; }
    if (a == 0) snprintf(buf, n, "0");
    else if (a < 10 && (i > 0 || a != (double)(int64_t)a)) snprintf(buf, n, "%.1f%s", v, u[i]);
    else snprintf(buf, n, "%.0f%s", v, u[i]);
    return buf;
}

char *fmt_duration(char *buf, size_t n, double s)
{
    if (s < 0) s = 0;
    if (s < 1.0) { snprintf(buf, n, "%.1f ms", s * 1000.0); return buf; }
    if (s < 60.0) { snprintf(buf, n, "%.3f s", s); return buf; }
    uint64_t t = (uint64_t)s;
    uint64_t d = t / 86400, h = (t / 3600) % 24, m = (t / 60) % 60, sec = t % 60;
    if (d) snprintf(buf, n, "%" PRIu64 "d %02" PRIu64 "h %02" PRIu64 "m", d, h, m);
    else if (h) snprintf(buf, n, "%" PRIu64 "h %02" PRIu64 "m %02" PRIu64 "s", h, m, sec);
    else snprintf(buf, n, "%" PRIu64 "m %02" PRIu64 "s", m, sec);
    return buf;
}

char *fmt_time_utc(char *buf, size_t n, int64_t ns)
{
    int64_t sec = ns / 1000000000LL;
    int64_t frac = ns % 1000000000LL;
    if (frac < 0) { frac += 1000000000LL; sec -= 1; }
    time_t t = (time_t)sec;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) { snprintf(buf, n, "(invalid time)"); return buf; }
    char d[32];
    strftime(d, sizeof d, "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf, n, "%s.%03d UTC", d, (int)(frac / 1000000));
    return buf;
}

int mkdir_p(const char *path)
{
    if (!path || !*path) { errno = EINVAL; return -1; }
    char *tmp = xstrdup(path);
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { free(tmp); return -1; }
        *p = '/';
    }
    int rc = 0;
    if (mkdir(tmp, 0755) != 0) {
        if (errno == EEXIST) {
            struct stat st;
            if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) { errno = ENOTDIR; rc = -1; }
        } else {
            rc = -1;
        }
    }
    free(tmp);
    return rc;
}

char *path_join(const char *dir, const char *name)
{
    size_t a = strlen(dir), b = strlen(name);
    int slash = (a > 0 && dir[a - 1] != '/');
    char *r = xmalloc(a + (size_t)slash + b + 1);
    memcpy(r, dir, a);
    if (slash) r[a] = '/';
    memcpy(r + a + (size_t)slash, name, b + 1);
    return r;
}
