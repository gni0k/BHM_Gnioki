#ifndef PCAPREPORT_CHART_H
#define PCAPREPORT_CHART_H

#include <stddef.h>
#include <stdint.h>
#include "raster.h"

/* Palette (validated categorical order, light surface). */
#define COL_SURFACE   RGB(0xfcfcfb)
#define COL_TEXT      RGB(0x0b0b0b)
#define COL_TEXT2     RGB(0x52514e)
#define COL_GRID      RGB(0xe7e6e2)
#define COL_AXIS      RGB(0xb9b8b1)
#define COL_SERIES1   RGB(0x2a78d6)
#define COL_SERIES2   RGB(0xeb6834)
#define COL_SERIES3   RGB(0x1baf7a)
#define COL_SERIES4   RGB(0xeda100)

#define CHART_W 900
#define CHART_H 450

typedef enum { YFMT_COUNT, YFMT_BITS, YFMT_BYTES, YFMT_PERCENT } yfmt_t;

typedef struct {
    const char *name;
    rgb_t color;
    const double *v;  /* n values */
} series_t;

/* Time series: stacked area (stacked=1) or plain lines. Values are per-second rates. */
void chart_timeline(canvas_t *c, const char *title, const char *subtitle, int64_t t0_ns, int64_t step_ns,
                    size_t n, const series_t *s, size_t ns, int stacked, yfmt_t fmt);

/* Horizontal bar chart; label[i]/value[i]; value_text[i] optional (NULL = auto). */
void chart_hbar(canvas_t *c, const char *title, const char *subtitle, const char *const *labels,
                const double *values, const char *const *value_text, size_t n, rgb_t color, yfmt_t fmt);
/* Height that chart_hbar needs for n rows. */
int chart_hbar_height(size_t n);

/* Vertical grouped bars: ncat categories, ns series (each series.v has ncat values). */
void chart_bars(canvas_t *c, const char *title, const char *subtitle, const char *const *cats, size_t ncat,
                const series_t *s, size_t ns, yfmt_t fmt);

#endif
