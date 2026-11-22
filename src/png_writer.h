#ifndef PCAPREPORT_PNG_WRITER_H
#define PCAPREPORT_PNG_WRITER_H

#include "raster.h"

/* Writes canvas as 8-bit RGB PNG. Returns 0 on success, -1 (errno set) on I/O error. */
int png_write(const canvas_t *c, const char *path);

#endif
