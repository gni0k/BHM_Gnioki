#define _POSIX_C_SOURCE 200809L
#include "chart.h"
#include "util.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define M_LEFT   84
#define M_RIGHT  28
#define M_TOP    78
#define M_BOTTOM 52

static void fmt_value(char *b, size_t n, double v, yfmt_t f)
{
    char t[32];
    switch (f) {
    case YFMT_BITS: {
        fmt_si(t, sizeof t, v); /* "15M" -> "15 Mbit/s", "500" -> "500 bit/s" */
        size_t l = strlen(t);
        char pfx[2] = {0, 0};
        if (l && t[l - 1] >= 'A') { pfx[0] = t[l - 1]; t[l - 1] = '\0'; }
        snprintf(b, n, "%s %sbit/s", t, pfx);
        break;
    }
    case YFMT_BYTES: fmt_bytes(b, n, v); break;
    case YFMT_PERCENT: snprintf(b, n, "%.1f%%", v); break;
    default: fmt_si(b, n, v); break;
    }
}

static void draw_header(canvas_t *c, const char *title, const char *subtitle)
{
    canvas_text(c, &font_bold, 20, 14, title, COL_TEXT);
    if (subtitle && *subtitle) canvas_text(c, &font_small, 20, 38, subtitle, COL_TEXT2);
}

/* Legend row above the plot (only drawn for >= 2 series). */
static void draw_legend(canvas_t *c, const series_t *s, size_t ns, int y)
{
    if (ns < 2) return;
    int x = M_LEFT;
    for (size_t i = 0; i < ns; i++) {
        canvas_fill_round_top(c, x, y + 3, 12, 12, 3, s[i].color);
        x += 18;
        x += canvas_text(c, &font_small, x, y, s[i].name, COL_TEXT2);
        x += 22;
    }
}

static void draw_empty(canvas_t *c, int px, int py, int pw, int ph)
{
    const char *m = "No data";
    canvas_text(c, &font_small, px + (pw - text_width(&font_small, m)) / 2, py + ph / 2 - 8, m, COL_TEXT2);
}

/* "Nice" axis maximum and step (1, 2, 2.5, 5 x 10^k). */
static double nice_step(double maxv, int ticks, double *nice_max)
{
    if (maxv <= 0) maxv = 1;
    double raw = maxv / ticks;
    double p = pow(10, floor(log10(raw)));
    double m = raw / p;
    double st = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
    st *= p;
    *nice_max = ceil(maxv / st - 1e-9) * st;
    return st;
}

/* vmax must already be a "nice" maximum from y_scale(); step from the same call. */
static void draw_y_axis(canvas_t *c, int px, int py, int pw, int ph, double vmax, double step, yfmt_t fmt)
{
    char lab[48];
    for (double v = 0; v <= vmax + step * 0.01; v += step) {
        int y = py + ph - (int)lround(v / vmax * ph);
        if (v > 0) canvas_hline(c, px, px + pw, y, COL_GRID);
        fmt_value(lab, sizeof lab, v, fmt);
        canvas_text(c, &font_small, px - 10 - text_width(&font_small, lab), y - 9, lab, COL_TEXT2);
    }
    canvas_hline(c, px, px + pw, py + ph, COL_AXIS);
}

static double y_scale(double vmax, double *step)
{
    double m;
    *step = nice_step(vmax, 5, &m);
    return m;
}

static void fmt_tick_time(char *b, size_t n, int64_t ns, int64_t tick, int64_t span)
{
    time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    if (!gmtime_r(&t, &tm)) { snprintf(b, n, "?"); return; }
    if (span >= 2LL * 86400 * 1000000000LL) strftime(b, n, "%m-%d %H:%M", &tm);
    else if (tick >= 60LL * 1000000000LL) strftime(b, n, "%H:%M", &tm);
    else if (tick >= 1000000000LL) strftime(b, n, "%H:%M:%S", &tm);
    else {
        char hms[16];
        strftime(hms, sizeof hms, "%M:%S", &tm);
        int ms = (int)((ns % 1000000000LL) / 1000000LL);
        if (ms < 0) ms += 1000;
        snprintf(b, n, "%s.%03d", hms, ms);
    }
}

void chart_timeline(canvas_t *c, const char *title, const char *subtitle, int64_t t0, int64_t step,
                    size_t n, const series_t *s, size_t ns, int stacked, yfmt_t fmt)
{
    canvas_init(c, CHART_W, CHART_H, COL_SURFACE);
    draw_header(c, title, subtitle);
    draw_legend(c, s, ns, 56);
    int px = M_LEFT, py = M_TOP + 8, pw = CHART_W - M_LEFT - M_RIGHT, ph = CHART_H - M_TOP - 8 - M_BOTTOM;
    if (n == 0 || ns == 0 || step <= 0) { draw_y_axis(c, px, py, pw, ph, 1, 0.2, fmt); draw_empty(c, px, py, pw, ph); return; }

    double vmax = 0;
    for (size_t i = 0; i < n; i++) {
        double acc = 0;
        for (size_t k = 0; k < ns; k++) {
            double v = s[k].v[i];
            if (stacked) acc += v; else acc = MAX(acc, v);
        }
        vmax = MAX(vmax, acc);
    }
    double ystep;
    double ymax = y_scale(vmax, &ystep);
    draw_y_axis(c, px, py, pw, ph, ymax, ystep, fmt);

    /* x mapping: bucket i is plotted at its centre */
    double xs = n > 1 ? (double)pw / (double)(n - 1) : 0;
#define XOF(i) (n > 1 ? px + (double)(i) * xs : px + pw / 2.0)
#define YOF(v) (py + ph - (v) / ymax * ph)

    /* Cumulative tops per series (stacked) or plain values. */
    double **top = xcalloc(ns, sizeof *top);
    for (size_t k = 0; k < ns; k++) {
        top[k] = xcalloc(n, sizeof *top[k]);
        for (size_t i = 0; i < n; i++) top[k][i] = (stacked && k ? top[k - 1][i] : 0) + s[k].v[i];
    }
    /* 1) translucent bands, bottom to top */
    if (stacked && n > 1) {
        for (size_t k = 0; k < ns; k++) {
            for (int x = px; x <= px + pw; x++) {
                double fi = (x - px) / xs;
                size_t i0 = (size_t)fi;
                if (i0 >= n - 1) i0 = n - 2;
                double fr = fi - (double)i0;
                double b = k ? top[k - 1][i0] * (1 - fr) + top[k - 1][i0 + 1] * fr : 0;
                double t = top[k][i0] * (1 - fr) + top[k][i0 + 1] * fr;
                int y0 = (int)lround(YOF(t)), y1 = (int)lround(YOF(b));
                for (int y = y0; y < y1; y++) canvas_blend(c, x, y, s[k].color, 72);
            }
        }
    }
    /* 2) outlines, last series first, so a lower band's edge is never hidden by an empty band above it */
    for (size_t kk = ns; kk-- > 0;) {
        if (n == 1) canvas_disc(c, XOF(0), YOF(top[kk][0]), 4, s[kk].color);
        for (size_t i = 0; i + 1 < n; i++)
            canvas_line(c, XOF(i), YOF(top[kk][i]), XOF(i + 1), YOF(top[kk][i + 1]), 2.0, s[kk].color);
    }
    for (size_t k = 0; k < ns; k++) free(top[k]);
    free(top);

    /* x ticks */
    static const int64_t ladder_ms[] = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 15000,
                                        30000, 60000, 120000, 300000, 600000, 900000, 1800000, 3600000,
                                        7200000, 10800000, 21600000, 43200000, 86400000, 172800000,
                                        604800000, 2592000000LL};
    int64_t span = (int64_t)n * step;
    int64_t tick = ladder_ms[ARRAY_LEN(ladder_ms) - 1] * 1000000LL;
    for (size_t i = 0; i < ARRAY_LEN(ladder_ms); i++)
        if (span / (ladder_ms[i] * 1000000LL) <= 7) { tick = ladder_ms[i] * 1000000LL; break; }
    int64_t tstart = t0 + step / 2;
    int64_t tend = t0 + (int64_t)(n - 1) * step + step / 2;
    int64_t first = (tstart / tick) * tick;
    if (first < tstart) first += tick;
    char lab[32];
    int last_right = -1000;
    for (int64_t t = first; t <= tend; t += tick) {
        double x = n > 1 ? px + (double)(t - tstart) / (double)(tend - tstart) * pw : px + pw / 2.0;
        canvas_vline(c, (int)lround(x), py + ph, py + ph + 5, COL_AXIS);
        fmt_tick_time(lab, sizeof lab, t, tick, span);
        int w = text_width(&font_small, lab);
        int lx = (int)lround(x) - w / 2;
        if (lx < 2) lx = 2;
        if (lx + w > CHART_W - 2) lx = CHART_W - 2 - w;
        if (lx > last_right + 8) {
            canvas_text(c, &font_small, lx, py + ph + 9, lab, COL_TEXT2);
            last_right = lx + w;
        }
    }
    const char *xl = "Time (UTC)";
    canvas_text(c, &font_small, px + pw - text_width(&font_small, xl), CHART_H - 22, xl, COL_TEXT2);
#undef XOF
#undef YOF
}

int chart_hbar_height(size_t n)
{
    if (n == 0) n = 1;
    return 70 + (int)n * 30 + 16;
}

void chart_hbar(canvas_t *c, const char *title, const char *subtitle, const char *const *labels,
                const double *values, const char *const *value_text, size_t n, rgb_t color, yfmt_t fmt)
{
    canvas_init(c, CHART_W, chart_hbar_height(n), COL_SURFACE);
    draw_header(c, title, subtitle);
    int lab_w = 0;
    for (size_t i = 0; i < n; i++) lab_w = MAX(lab_w, text_width(&font_small, labels[i]));
    lab_w = MIN(lab_w, 330);
    int px = 20 + lab_w + 12, py = 70, pw = CHART_W - px - 130;
    if (n == 0) { draw_empty(c, 20, py, CHART_W - 40, 30); return; }
    double vmax = 0;
    for (size_t i = 0; i < n; i++) vmax = MAX(vmax, values[i]);
    if (vmax <= 0) vmax = 1;
    char vb[64], lb[128];
    for (size_t i = 0; i < n; i++) {
        int y = py + (int)i * 30;
        /* label, truncated with "..." if needed */
        snprintf(lb, sizeof lb, "%s", labels[i]);
        while (text_width(&font_small, lb) > lab_w && strlen(lb) > 4) {
            size_t l = strlen(lb);
            lb[l - 4] = '.'; lb[l - 3] = '.'; lb[l - 2] = '.'; lb[l - 1] = '\0';
        }
        canvas_text(c, &font_small, px - 12 - text_width(&font_small, lb), y + 4, lb, COL_TEXT);
        int bw = (int)lround(values[i] / vmax * pw);
        if (values[i] > 0 && bw < 2) bw = 2;
        canvas_fill_round_right(c, px, y + 3, bw, 22, 4, color);
        if (value_text && value_text[i]) snprintf(vb, sizeof vb, "%s", value_text[i]);
        else fmt_value(vb, sizeof vb, values[i], fmt);
        canvas_text(c, &font_small, px + bw + 8, y + 4, vb, COL_TEXT2);
    }
    canvas_vline(c, px, py, py + (int)n * 30, COL_AXIS);
}

void chart_bars(canvas_t *c, const char *title, const char *subtitle, const char *const *cats, size_t ncat,
                const series_t *s, size_t ns, yfmt_t fmt)
{
    canvas_init(c, CHART_W, CHART_H, COL_SURFACE);
    draw_header(c, title, subtitle);
    draw_legend(c, s, ns, 56);
    int px = M_LEFT, py = M_TOP + 8, pw = CHART_W - M_LEFT - M_RIGHT, ph = CHART_H - M_TOP - 8 - M_BOTTOM;
    if (ncat == 0 || ns == 0) { draw_y_axis(c, px, py, pw, ph, 1, 0.2, fmt); draw_empty(c, px, py, pw, ph); return; }
    double vmax = 0;
    for (size_t k = 0; k < ns; k++)
        for (size_t i = 0; i < ncat; i++) vmax = MAX(vmax, s[k].v[i]);
    double ystep;
    double ymax = y_scale(vmax, &ystep);
    draw_y_axis(c, px, py, pw, ph, ymax, ystep, fmt);
    double slot = (double)pw / (double)ncat;
    int group_w = (int)(slot * 0.72);
    int gap = 2;
    int bw = (group_w - gap * (int)(ns - 1)) / (int)ns;
    if (bw < 2) bw = 2;
    for (size_t i = 0; i < ncat; i++) {
        int gx = px + (int)lround(slot * (double)i + (slot - group_w) / 2.0);
        for (size_t k = 0; k < ns; k++) {
            double v = s[k].v[i];
            int h = (int)lround(v / ymax * ph);
            if (v > 0 && h < 2) h = 2;
            canvas_fill_round_top(c, gx + (int)k * (bw + gap), py + ph - h, bw, h, 4, s[k].color);
        }
        int w = text_width(&font_small, cats[i]);
        canvas_text(c, &font_small, px + (int)lround(slot * (double)i + slot / 2.0) - w / 2, py + ph + 9,
                    cats[i], COL_TEXT2);
    }
    canvas_hline(c, px, px + pw, py + ph, COL_AXIS);
}
