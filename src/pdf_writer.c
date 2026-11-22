#define _POSIX_C_SOURCE 200809L
#include "pdf_writer.h"
#include "util.h"
#include "zcompat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Standard AFM advance widths (1/1000 em) for 0x20..0x7E. */
static const unsigned short helv_w[95] = {
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778,
    722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
    278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584};
static const unsigned short helvb_w[95] = {
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778,
    722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333,
    278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584};

typedef struct {
    buf_t data; /* compressed RGB */
    int w, h;
} pdf_image_t;

struct pdf {
    char *title;
    char *footer;
    buf_t *pages;      /* content stream per page (uncompressed) */
    size_t npages;
    pdf_image_t *imgs;
    size_t nimgs;
};

pdf_t *pdf_new(const char *title)
{
    pdf_t *p = xcalloc(1, sizeof *p);
    p->title = xstrdup(title ? title : "Report");
    return p;
}

void pdf_free(pdf_t *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->npages; i++) buf_free(&p->pages[i]);
    for (size_t i = 0; i < p->nimgs; i++) buf_free(&p->imgs[i].data);
    free(p->pages);
    free(p->imgs);
    free(p->title);
    free(p->footer);
    free(p);
}

void pdf_new_page(pdf_t *p)
{
    p->pages = xreallocarray(p->pages, p->npages + 1, sizeof *p->pages);
    buf_init(&p->pages[p->npages++]);
}

size_t pdf_page_count(const pdf_t *p) { return p->npages; }

static buf_t *cur(pdf_t *p)
{
    if (!p->npages) pdf_new_page(p);
    return &p->pages[p->npages - 1];
}

static void color_op(buf_t *b, rgb_t c, int stroke)
{
    buf_printf(b, "%.3f %.3f %.3f %s\n", c.r / 255.0, c.g / 255.0, c.b / 255.0, stroke ? "RG" : "rg");
}

double pdf_text_width(pdf_font_t f, double size, const char *s)
{
    double w = 0;
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        int i = (*c >= 32 && *c <= 126) ? *c - 32 : '?' - 32;
        w += f == PDF_FONT_MONO ? 600 : f == PDF_FONT_BOLD ? helvb_w[i] : helv_w[i];
    }
    return w * size / 1000.0;
}

static void append_pdf_string(buf_t *b, const char *s)
{
    buf_append(b, "(", 1);
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        unsigned char ch = (*c >= 32 && *c <= 126) ? *c : '?';
        if (ch == '(' || ch == ')' || ch == '\\') buf_append(b, "\\", 1);
        buf_append(b, &ch, 1);
    }
    buf_append(b, ")", 1);
}

void pdf_text(pdf_t *p, pdf_font_t f, double size, double x, double y, const char *s, rgb_t col)
{
    buf_t *b = cur(p);
    buf_append_str(b, "BT\n");
    color_op(b, col, 0);
    buf_printf(b, "/F%d %.2f Tf\n%.2f %.2f Td\n", (int)f + 1, size, x, PDF_PAGE_H - y);
    append_pdf_string(b, s);
    buf_append_str(b, " Tj\nET\n");
}

void pdf_fill_rect(pdf_t *p, double x, double y, double w, double h, rgb_t col)
{
    buf_t *b = cur(p);
    color_op(b, col, 0);
    buf_printf(b, "%.2f %.2f %.2f %.2f re f\n", x, PDF_PAGE_H - y - h, w, h);
}

void pdf_line(pdf_t *p, double x0, double y0, double x1, double y1, double width, rgb_t col)
{
    buf_t *b = cur(p);
    color_op(b, col, 1);
    buf_printf(b, "%.2f w %.2f %.2f m %.2f %.2f l S\n", width, x0, PDF_PAGE_H - y0, x1, PDF_PAGE_H - y1);
}

int pdf_add_image(pdf_t *p, const canvas_t *c)
{
    p->imgs = xreallocarray(p->imgs, p->nimgs + 1, sizeof *p->imgs);
    pdf_image_t *im = &p->imgs[p->nimgs];
    buf_init(&im->data);
    im->w = c->w;
    im->h = c->h;
    z_compress(c->px, (size_t)c->w * (size_t)c->h * 3u, &im->data);
    return (int)p->nimgs++;
}

void pdf_draw_image(pdf_t *p, int img, double x, double y, double w, double h)
{
    if (img < 0 || (size_t)img >= p->nimgs) return;
    buf_printf(cur(p), "q %.2f 0 0 %.2f %.2f %.2f cm /Im%d Do Q\n", w, h, x, PDF_PAGE_H - y - h, img);
}

void pdf_set_footer(pdf_t *p, const char *text)
{
    free(p->footer);
    p->footer = text ? xstrdup(text) : NULL;
}

/* ---------------------------------------------------------------- output */

typedef struct {
    buf_t out;
    long *offs;
    size_t nobj, cap;
} writer_t;

static size_t obj_begin(writer_t *w, size_t id)
{
    if (id >= w->cap) {
        size_t nc = w->cap ? w->cap : 64;
        while (nc <= id) nc *= 2;
        w->offs = xreallocarray(w->offs, nc, sizeof *w->offs);
        for (size_t i = w->cap; i < nc; i++) w->offs[i] = -1;
        w->cap = nc;
    }
    w->offs[id] = (long)w->out.len;
    if (id + 1 > w->nobj) w->nobj = id + 1;
    buf_printf(&w->out, "%zu 0 obj\n", id);
    return id;
}

static void stream_obj(writer_t *w, size_t id, const char *dict_extra, const buf_t *data)
{
    obj_begin(w, id);
    buf_printf(&w->out, "<< /Length %zu /Filter /FlateDecode %s >>\nstream\n", data->len, dict_extra ? dict_extra : "");
    buf_append(&w->out, data->data, data->len);
    buf_append_str(&w->out, "\nendstream\nendobj\n");
}

int pdf_save(pdf_t *p, const char *path)
{
    if (!p->npages) pdf_new_page(p);
    /* Object numbering:
     * 1 catalog, 2 pages, 3 info, 4..6 fonts, 7.. images, then (page, content) pairs. */
    const size_t first_img = 7, first_page = first_img + p->nimgs;
    writer_t w;
    memset(&w, 0, sizeof w);
    buf_init(&w.out);
    buf_append_str(&w.out, "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    obj_begin(&w, 1);
    buf_append_str(&w.out, "<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    obj_begin(&w, 2);
    buf_printf(&w.out, "<< /Type /Pages /Count %zu /Kids [", p->npages);
    for (size_t i = 0; i < p->npages; i++) buf_printf(&w.out, " %zu 0 R", first_page + 2 * i);
    buf_append_str(&w.out, " ] >>\nendobj\n");

    char date[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(date, sizeof date, "D:%Y%m%d%H%M%SZ", &tm);
    obj_begin(&w, 3);
    buf_append_str(&w.out, "<< /Title ");
    append_pdf_string(&w.out, p->title);
    buf_printf(&w.out, " /Producer (pcapreport) /Creator (pcapreport) /CreationDate (%s) >>\nendobj\n", date);

    static const char *fonts[] = {"Helvetica", "Helvetica-Bold", "Courier"};
    for (size_t i = 0; i < 3; i++) {
        obj_begin(&w, 4 + i);
        buf_printf(&w.out, "<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>\nendobj\n",
                   fonts[i]);
    }
    for (size_t i = 0; i < p->nimgs; i++) {
        char extra[160];
        snprintf(extra, sizeof extra, "/Type /XObject /Subtype /Image /Width %d /Height %d "
                 "/ColorSpace /DeviceRGB /BitsPerComponent 8", p->imgs[i].w, p->imgs[i].h);
        stream_obj(&w, first_img + i, extra, &p->imgs[i].data);
    }

    buf_t xobj;
    buf_init(&xobj);
    for (size_t i = 0; i < p->nimgs; i++) buf_printf(&xobj, " /Im%zu %zu 0 R", i, first_img + i);
    buf_append(&xobj, "", 1); /* NUL-terminate for %s */

    for (size_t i = 0; i < p->npages; i++) {
        size_t pid = first_page + 2 * i, cid = pid + 1;
        obj_begin(&w, pid);
        buf_printf(&w.out, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Contents %zu 0 R "
                   "/Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >>",
                   PDF_PAGE_W, PDF_PAGE_H, cid);
        if (p->nimgs) buf_printf(&w.out, " /XObject <<%s >>", (const char *)xobj.data);
        buf_append_str(&w.out, " >> >>\nendobj\n");

        /* footer is added here because the total page count is only known now */
        buf_t *pg = &p->pages[i];
        size_t saved_len = pg->len;
        rgb_t grey = RGB(0x6b6a65);
        char num[64];
        snprintf(num, sizeof num, "Page %zu of %zu", i + 1, p->npages);
        buf_printf(pg, "0.85 0.85 0.83 RG 0.5 w 40 %.2f m %.2f %.2f l S\n", 32.0, PDF_PAGE_W - 40, 32.0);
        if (p->footer) {
            buf_append_str(pg, "BT\n");
            color_op(pg, grey, 0);
            buf_printf(pg, "/F1 8 Tf\n40 20 Td\n");
            append_pdf_string(pg, p->footer);
            buf_append_str(pg, " Tj\nET\n");
        }
        buf_append_str(pg, "BT\n");
        color_op(pg, grey, 0);
        buf_printf(pg, "/F1 8 Tf\n%.2f 20 Td\n", PDF_PAGE_W - 40 - pdf_text_width(PDF_FONT_REGULAR, 8, num));
        append_pdf_string(pg, num);
        buf_append_str(pg, " Tj\nET\n");

        buf_t z;
        buf_init(&z);
        z_compress(pg->data ? pg->data : (const unsigned char *)"", pg->len, &z);
        pg->len = saved_len; /* leave page content unchanged */
        stream_obj(&w, cid, NULL, &z);
        buf_free(&z);
    }
    buf_free(&xobj);

    long xref = (long)w.out.len;
    buf_printf(&w.out, "xref\n0 %zu\n0000000000 65535 f \n", w.nobj);
    for (size_t i = 1; i < w.nobj; i++) {
        if (w.offs[i] < 0) buf_append_str(&w.out, "0000000000 65535 f \n");
        else buf_printf(&w.out, "%010ld 00000 n \n", w.offs[i]);
    }
    buf_printf(&w.out, "trailer\n<< /Size %zu /Root 1 0 R /Info 3 0 R >>\nstartxref\n%ld\n%%%%EOF\n", w.nobj, xref);

    int rc = 0;
    FILE *fp = fopen(path, "wb");
    if (!fp) rc = -1;
    else {
        if (fwrite(w.out.data, 1, w.out.len, fp) != w.out.len) rc = -1;
        int saved = errno;
        if (fclose(fp) != 0) rc = -1;
        else if (rc) errno = saved;
    }
    buf_free(&w.out);
    free(w.offs);
    return rc;
}
