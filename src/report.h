#ifndef PCAPREPORT_REPORT_H
#define PCAPREPORT_REPORT_H

#include <stddef.h>
#include <stdio.h>
#include "analyzer.h"
#include "anomaly.h"

typedef struct {
    const char *outdir;
    const char *title;
    size_t top_n;
    int want_pdf;
    int want_png;
} report_opts_t;

/* Writes report.pdf and/or the PNG charts into outdir. Returns 0 on success, -1 on error. */
int report_generate(const analyzer_t *an, const results_t *res, const report_opts_t *opts);

/* Prints a plain-text summary with all findings (for terminals and scripts). */
void report_print_summary(FILE *fp, const analyzer_t *an, const results_t *res);

#endif
