#ifndef KPERF_HELPERS_H
#define KPERF_HELPERS_H

#include <unistd.h>

void configure_kperf_stacks_timer(pid_t pid, unsigned int period_ms);

#endif /* !defined(KPERF_HELPERS_H) */
