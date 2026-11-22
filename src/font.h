#ifndef PCAPREPORT_FONT_H
#define PCAPREPORT_FONT_H

/* Bitmap font: printable ASCII 0x20..0x7E, 8-bit alpha, fixed cell, proportional advance. */
typedef struct {
    int cell_w;                  /* bitmap cell width in pixels  */
    int cell_h;                  /* bitmap cell height in pixels */
    int ascent;                  /* baseline offset from top     */
    const unsigned char *adv;    /* advance width per glyph [95] */
    const unsigned char *bits;   /* 95 * cell_w * cell_h alpha   */
} font_t;

extern const font_t font_small;
extern const font_t font_bold;

#endif
