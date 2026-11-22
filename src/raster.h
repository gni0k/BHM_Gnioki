#ifndef PCAPREPORT_RASTER_H
#define PCAPREPORT_RASTER_H

#include <stdint.h>
#include "font.h"

typedef struct { uint8_t r, g, b; } rgb_t;

#define RGB(hex) ((rgb_t){ (uint8_t)(((hex) >> 16) & 0xFF), (uint8_t)(((hex) >> 8) & 0xFF), (uint8_t)((hex) & 0xFF) })

/* 24-bit RGB canvas, row-major, no padding. */
typedef struct {
    int w, h;
    uint8_t *px;
} canvas_t;

void canvas_init(canvas_t *c, int w, int h, rgb_t bg);
void canvas_free(canvas_t *c);
void canvas_blend(canvas_t *c, int x, int y, rgb_t col, int alpha /* 0..255 */);
void canvas_fill_rect(canvas_t *c, int x, int y, int w, int h, rgb_t col);
void canvas_fill_rect_alpha(canvas_t *c, int x, int y, int w, int h, rgb_t col, int alpha);
/* Bar with rounded corners at the top (radius r). */
void canvas_fill_round_top(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col);
/* Bar with rounded corners at the right end (horizontal bars). */
void canvas_fill_round_right(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col);
void canvas_hline(canvas_t *c, int x0, int x1, int y, rgb_t col);
void canvas_vline(canvas_t *c, int x, int y0, int y1, rgb_t col);
/* Anti-aliased line of given width (float coordinates). */
void canvas_line(canvas_t *c, double x0, double y0, double x1, double y1, double width, rgb_t col);
void canvas_disc(canvas_t *c, double cx, double cy, double r, rgb_t col);

/* Text: y is the top of the text line. Returns advance width. Non-ASCII -> '?'. */
int text_width(const font_t *f, const char *s);
int canvas_text(canvas_t *c, const font_t *f, int x, int y, const char *s, rgb_t col);
/* Text rotated 90 degrees counter-clockwise; (x, y) = bottom-left of the run. */
void canvas_text_vertical(canvas_t *c, const font_t *f, int x, int y, const char *s, rgb_t col);

#endif
