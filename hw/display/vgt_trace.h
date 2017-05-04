#ifndef _VGT_TRACE_
#define _VGT_TRACE_


#define DEBUG_VGT
#ifdef DEBUG_VGT
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "TRACE_VGT: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

void vgt_start_tracing(void);


#endif
