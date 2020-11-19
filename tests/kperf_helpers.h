#ifndef KPERF_HELPERS_H
#define KPERF_HELPERS_H

#include <unistd.h>
#include <stdbool.h>

void configure_kperf_stacks_timer(pid_t pid, unsigned int period_ms,
    bool quiet);

#define PERF_SAMPLE KDBG_EVENTID(DBG_PERF, 0, 0)
#define PERF_KPC_PMI KDBG_EVENTID(DBG_PERF, 6, 0)

#endif /* !defined(KPERF_HELPERS_H) */
