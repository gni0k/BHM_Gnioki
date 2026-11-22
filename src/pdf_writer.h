#ifndef PCAPREPORT_PDF_WRITER_H
#define PCAPREPORT_PDF_WRITER_H

#include <stddef.h>
#include "raster.h"

/*
 * Minimal PDF 1.4 writer: A4 pages, the standard Type 1 fonts Helvetica,
 * Helvetica-Bold and Courier (no embedding required, WinAnsi encoding),
 * filled rectangles, lines and RGB raster images (FlateDecode).
 * The coordinate system used by this API has its origin in the TOP-LEFT
 * corner, y growing downwards, units = PostScript points (1/72 inch).
 */

#define PDF_PAGE_W 595.28
#define PDF_PAGE_H 841.89

typedef enum { PDF_FONT_REGULAR = 0, PDF_FONT_BOLD = 1, PDF_FONT_MONO = 2 } pdf_font_t;

typedef struct pdf pdf_t;

pdf_t *pdf_new(const char *title);
void pdf_free(pdf_t *p);
void pdf_new_page(pdf_t *p);
size_t pdf_page_count(const pdf_t *p);
/* Text drawn with baseline at y. */
void pdf_text(pdf_t *p, pdf_font_t f, double size, double x, double y, const char *s, rgb_t col);
double pdf_text_width(pdf_font_t f, double size, const char *s);
void pdf_fill_rect(pdf_t *p, double x, double y, double w, double h, rgb_t col);
void pdf_line(pdf_t *p, double x0, double y0, double x1, double y1, double width, rgb_t col);
/* Registers an image (copies & compresses the pixels); returns its handle. */
int pdf_add_image(pdf_t *p, const canvas_t *c);
void pdf_draw_image(pdf_t *p, int img, double x, double y, double w, double h);
/* Footer text printed on every page together with "Page i of N". */
void pdf_set_footer(pdf_t *p, const char *text);
/* Writes the document; returns 0 on success, -1 on I/O error (errno set). */
int pdf_save(pdf_t *p, const char *path);

#endif
