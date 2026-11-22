#include "raster.h"
#include "util.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

void canvas_init(canvas_t *c, int w, int h, rgb_t bg)
{
    c->w = w;
    c->h = h;
    c->px = xmalloc((size_t)w * (size_t)h * 3u);
    for (size_t i = 0; i < (size_t)w * (size_t)h; i++) {
        c->px[i * 3] = bg.r;
        c->px[i * 3 + 1] = bg.g;
        c->px[i * 3 + 2] = bg.b;
    }
}

void canvas_free(canvas_t *c)
{
    free(c->px);
    c->px = NULL;
    c->w = c->h = 0;
}

void canvas_blend(canvas_t *c, int x, int y, rgb_t col, int a)
{
    if (x < 0 || y < 0 || x >= c->w || y >= c->h || a <= 0) return;
    if (a > 255) a = 255;
    uint8_t *p = c->px + ((size_t)y * (size_t)c->w + (size_t)x) * 3u;
    p[0] = (uint8_t)((p[0] * (255 - a) + col.r * a + 127) / 255);
    p[1] = (uint8_t)((p[1] * (255 - a) + col.g * a + 127) / 255);
    p[2] = (uint8_t)((p[2] * (255 - a) + col.b * a + 127) / 255);
}

void canvas_fill_rect_alpha(canvas_t *c, int x, int y, int w, int h, rgb_t col, int alpha)
{
    int x0 = MAX(x, 0), y0 = MAX(y, 0);
    int x1 = MIN(x + w, c->w), y1 = MIN(y + h, c->h);
    for (int yy = y0; yy < y1; yy++)
        for (int xx = x0; xx < x1; xx++) canvas_blend(c, xx, yy, col, alpha);
}

void canvas_fill_rect(canvas_t *c, int x, int y, int w, int h, rgb_t col)
{
    canvas_fill_rect_alpha(c, x, y, w, h, col, 255);
}

/* Coverage of pixel (px,py) by a circle centred (cx,cy) radius r, 4x4 supersampled. */
static int circle_cov(double px, double py, double cx, double cy, double r)
{
    int n = 0;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            double sx = px + (i + 0.5) / 4.0 - cx, sy = py + (j + 0.5) / 4.0 - cy;
            if (sx * sx + sy * sy <= r * r) n++;
        }
    return n * 255 / 16;
}

void canvas_fill_round_top(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col)
{
    if (w <= 0 || h <= 0) return;
    if (r * 2 > w) r = w / 2;
    if (r > h) r = h;
    canvas_fill_rect(c, x, y + r, w, h - r, col);
    canvas_fill_rect(c, x + r, y, w - 2 * r, r, col);
    for (int yy = y; yy < y + r; yy++)
        for (int xx = 0; xx < r; xx++) {
            canvas_blend(c, x + xx, yy, col, circle_cov(x + xx, yy, x + r, y + r, r));
            canvas_blend(c, x + w - 1 - xx, yy, col, circle_cov(x + w - 1 - xx, yy, x + w - r, y + r, r));
        }
}

void canvas_fill_round_right(canvas_t *c, int x, int y, int w, int h, int r, rgb_t col)
{
    if (w <= 0 || h <= 0) return;
    if (r * 2 > h) r = h / 2;
    if (r > w) r = w;
    canvas_fill_rect(c, x, y, w - r, h, col);
    canvas_fill_rect(c, x + w - r, y + r, r, h - 2 * r, col);
    for (int xx = x + w - r; xx < x + w; xx++)
        for (int yy = 0; yy < r; yy++) {
            canvas_blend(c, xx, y + yy, col, circle_cov(xx, y + yy, x + w - r, y + r, r));
            canvas_blend(c, xx, y + h - 1 - yy, col, circle_cov(xx, y + h - 1 - yy, x + w - r, y + h - r, r));
        }
}

void canvas_hline(canvas_t *c, int x0, int x1, int y, rgb_t col)
{
    if (x1 < x0) { int t = x0; x0 = x1; x1 = t; }
    canvas_fill_rect(c, x0, y, x1 - x0 + 1, 1, col);
}

void canvas_vline(canvas_t *c, int x, int y0, int y1, rgb_t col)
{
    if (y1 < y0) { int t = y0; y0 = y1; y1 = t; }
    canvas_fill_rect(c, x, y0, 1, y1 - y0 + 1, col);
}

void canvas_line(canvas_t *c, double x0, double y0, double x1, double y1, double width, rgb_t col)
{
    double hw = width / 2.0;
    int bx0 = (int)floor(MIN(x0, x1) - hw - 1), bx1 = (int)ceil(MAX(x0, x1) + hw + 1);
    int by0 = (int)floor(MIN(y0, y1) - hw - 1), by1 = (int)ceil(MAX(y0, y1) + hw + 1);
    bx0 = MAX(bx0, 0); by0 = MAX(by0, 0);
    bx1 = MIN(bx1, c->w - 1); by1 = MIN(by1, c->h - 1);
    double dx = x1 - x0, dy = y1 - y0;
    double len2 = dx * dx + dy * dy;
    for (int y = by0; y <= by1; y++)
        for (int x = bx0; x <= bx1; x++) {
            double px = x + 0.5, py = y + 0.5;
            double t = len2 > 0 ? ((px - x0) * dx + (py - y0) * dy) / len2 : 0;
            if (t < 0) t = 0;
            if (t > 1) t = 1;
            double qx = x0 + t * dx - px, qy = y0 + t * dy - py;
            double d = sqrt(qx * qx + qy * qy);
            double cov = hw + 0.5 - d;
            if (cov <= 0) continue;
            if (cov > 1) cov = 1;
            /* max-blend along the line avoids darkening at segment joins */
            uint8_t *p = c->px + ((size_t)y * (size_t)c->w + (size_t)x) * 3u;
            int a = (int)(cov * 255);
            uint8_t nr = (uint8_t)((p[0] * (255 - a) + col.r * a) / 255);
            uint8_t ng = (uint8_t)((p[1] * (255 - a) + col.g * a) / 255);
            uint8_t nb = (uint8_t)((p[2] * (255 - a) + col.b * a) / 255);
            p[0] = nr; p[1] = ng; p[2] = nb;
        }
}

void canvas_disc(canvas_t *c, double cx, double cy, double r, rgb_t col)
{
    for (int y = (int)(cy - r - 1); y <= (int)(cy + r + 1); y++)
        for (int x = (int)(cx - r - 1); x <= (int)(cx + r + 1); x++)
            canvas_blend(c, x, y, col, circle_cov(x, y, cx, cy, r));
}

static int glyph_index(unsigned char ch)
{
    if (ch < 32 || ch > 126) ch = '?';
    return ch - 32;
}

int text_width(const font_t *f, const char *s)
{
    int w = 0;
    for (; *s; s++) w += f->adv[glyph_index((unsigned char)*s)];
    return w;
}

int canvas_text(canvas_t *c, const font_t *f, int x, int y, const char *s, rgb_t col)
{
    int x0 = x;
    for (; *s; s++) {
        int g = glyph_index((unsigned char)*s);
        const unsigned char *bm = f->bits + (size_t)g * (size_t)(f->cell_w * f->cell_h);
        for (int gy = 0; gy < f->cell_h; gy++)
            for (int gx = 0; gx < f->cell_w; gx++) {
                int a = bm[gy * f->cell_w + gx];
                if (a) canvas_blend(c, x + gx, y + gy, col, a);
            }
        x += f->adv[g];
    }
    return x - x0;
}

void canvas_text_vertical(canvas_t *c, const font_t *f, int x, int y, const char *s, rgb_t col)
{
    for (; *s; s++) {
        int g = glyph_index((unsigned char)*s);
        const unsigned char *bm = f->bits + (size_t)g * (size_t)(f->cell_w * f->cell_h);
        for (int gy = 0; gy < f->cell_h; gy++)
            for (int gx = 0; gx < f->cell_w; gx++) {
                int a = bm[gy * f->cell_w + gx];
                if (a) canvas_blend(c, x + gy, y - gx, col, a);
            }
        y -= f->adv[g];
    }
}
