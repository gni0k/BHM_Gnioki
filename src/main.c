/*
 * pcapreport - TCP/UDP traffic analysis of pcap/pcapng files with PDF + PNG output.
 */
#define _POSIX_C_SOURCE 200809L
#include "analyzer.h"
#include "anomaly.h"
#include "report.h"
#include "util.h"
#include "version.h"
#include "zcompat.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { EXIT_USAGE = 1, EXIT_NO_INPUT = 2, EXIT_PARTIAL_INPUT = 3, EXIT_OUTPUT = 4 };

static void usage(FILE *fp)
{
    fprintf(fp,
            "Usage: pcapreport [options] FILE.pcap [FILE2.pcapng ...]\n"
            "\n"
            "Analyses TCP/UDP traffic in one or more capture files and writes a PDF report\n"
            "and PNG charts. Use '-' to read a capture from standard input.\n"
            "\n"
            "Options:\n"
            "  -o, --output DIR      output directory (default: ./pcapreport-out)\n"
            "  -t, --title TEXT      report title (default: \"Network Traffic Analysis Report\")\n"
            "  -n, --top N           entries in top-N tables and charts, 1-50 (default: 10)\n"
            "      --max-flows N     max. tracked flows (default: 1000000, ~%zu bytes each)\n"
            "      --max-hosts N     max. tracked hosts (default: 1000000)\n"
            "      --no-checksum     do not verify IPv4/TCP/UDP checksums\n"
            "      --no-pdf          do not write report.pdf\n"
            "      --no-png          do not write PNG charts\n"
            "  -s, --summary         print a text summary with all findings to stdout\n"
            "  -q, --quiet           only print errors\n"
            "  -v, --verbose         print progress information\n"
            "  -V, --version         print version and exit\n"
            "  -h, --help            print this help and exit\n"
            "\n"
            "Exit status: 0 success, 1 usage error, 2 no input could be read,\n"
            "             3 report written but some inputs failed, 4 output error.\n",
            sizeof(flow_t));
}

static int parse_size(const char *s, size_t lo, size_t hi, size_t *out)
{
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *end || s[0] == '-' || v < lo || v > hi) return -1;
    *out = (size_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    const char *outdir = "pcapreport-out";
    const char *title = "Network Traffic Analysis Report";
    size_t top = 10;
    analyzer_opts_t aopts = {.verify_checksums = 1, .max_flows = 1000000, .max_hosts = 1000000};
    int want_pdf = 1, want_png = 1, summary = 0;

    enum { OPT_MAX_FLOWS = 256, OPT_MAX_HOSTS, OPT_NO_CSUM, OPT_NO_PDF, OPT_NO_PNG };
    static const struct option longopts[] = {
        {"output", required_argument, NULL, 'o'},   {"title", required_argument, NULL, 't'},
        {"top", required_argument, NULL, 'n'},      {"max-flows", required_argument, NULL, OPT_MAX_FLOWS},
        {"max-hosts", required_argument, NULL, OPT_MAX_HOSTS}, {"no-checksum", no_argument, NULL, OPT_NO_CSUM},
        {"no-pdf", no_argument, NULL, OPT_NO_PDF},  {"no-png", no_argument, NULL, OPT_NO_PNG},
        {"summary", no_argument, NULL, 's'},        {"quiet", no_argument, NULL, 'q'},          {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "o:t:n:sqvVh", longopts, NULL)) != -1) {
        switch (c) {
        case 'o': outdir = optarg; break;
        case 't': title = optarg; break;
        case 'n':
            if (parse_size(optarg, 1, 50, &top) != 0) { log_error("--top expects 1..50"); return EXIT_USAGE; }
            break;
        case OPT_MAX_FLOWS:
            if (parse_size(optarg, 1, 100000000, &aopts.max_flows) != 0) {
                log_error("--max-flows expects 1..100000000");
                return EXIT_USAGE;
            }
            break;
        case OPT_MAX_HOSTS:
            if (parse_size(optarg, 1, 100000000, &aopts.max_hosts) != 0) {
                log_error("--max-hosts expects 1..100000000");
                return EXIT_USAGE;
            }
            break;
        case OPT_NO_CSUM: aopts.verify_checksums = 0; break;
        case OPT_NO_PDF: want_pdf = 0; break;
        case OPT_NO_PNG: want_png = 0; break;
        case 's': summary = 1; break;
        case 'q': g_verbosity = 0; break;
        case 'v': g_verbosity = 2; break;
        case 'V': printf("pcapreport %s (compression: %s)\n", VERSION_STR, z_backend()); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return EXIT_USAGE;
        }
    }
    if (optind >= argc) {
        log_error("no input files given");
        usage(stderr);
        return EXIT_USAGE;
    }
    if (!want_pdf && !want_png) {
        log_error("--no-pdf and --no-png together leave nothing to do");
        return EXIT_USAGE;
    }
    int stdin_used = 0;
    for (int i = optind; i < argc; i++)
        if (strcmp(argv[i], "-") == 0 && stdin_used++) {
            log_error("standard input ('-') can be given only once");
            return EXIT_USAGE;
        }

    analyzer_t an;
    analyzer_init(&an, &aopts);
    int ok = 0, failed = 0;
    for (int i = optind; i < argc; i++) {
        log_info("reading %s", argv[i]);
        if (analyzer_process_file(&an, argv[i]) == 0) ok++;
        else failed++;
    }
    if (!ok) {
        log_error("none of the input files could be read; no report produced");
        analyzer_free(&an);
        return EXIT_NO_INPUT;
    }
    log_info("%" PRIu64 " packets, %zu flows, %zu hosts", an.packets, an.flows.count, an.hosts.count);

    results_t res;
    results_compute(&an, &res);
    report_opts_t ro = {.outdir = outdir, .title = title, .top_n = top, .want_pdf = want_pdf, .want_png = want_png};
    int rc = report_generate(&an, &res, &ro);
    if (summary) report_print_summary(stdout, &an, &res);
    if (rc == 0 && g_verbosity >= 1) {
        fprintf(stderr, "pcapreport: %zu finding(s): %zu high, %zu medium, %zu info\n", res.nfindings,
                res.sev_count[SEV_HIGH], res.sev_count[SEV_MEDIUM], res.sev_count[SEV_INFO]);
    }
    results_free(&res);
    analyzer_free(&an);
    if (rc != 0) return EXIT_OUTPUT;
    return failed ? EXIT_PARTIAL_INPUT : 0;
}
