#if 0
CC = clang
    CFLAGS = -O3
    $(MAKEFILE_LIST:.c = ):

            ifeq (0, 1)
            * /
#endif

/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <getopt.h>

#include "../ksancov.h"

            static void
            usage(void)
	    {
		    fprintf(stderr,
		    "usage: ./ksancov [OPTIONS]\n\n"
		    "  -t | --trace        use trace (PC log) mode [default]\n"
		    "  -c | --counters     use edge counter mode\n"
		    "  -n | --entries <n>  override max entries in trace log\n"
		    "  -x | --exec <path>  instrument execution of binary at <path>\n");
		    exit(1);
	    }

            int
            main(int argc, char *argv[])
	    {
		    struct ksancov_trace *trace = NULL;
		    struct ksancov_counters *counters = NULL;
		    struct ksancov_header *header = NULL;

		    int ret;
		    size_t max_entries = 64UL * 1024;
		    char *path = NULL;
		    bool docounters = false;

		    struct option opts[] = {
			    { "entries", required_argument, NULL, 'n' },
			    { "exec", required_argument, NULL, 'x' },

			    { "trace", no_argument, NULL, 't' },
			    { "counters", no_argument, NULL, 'c' },

			    { NULL, 0, NULL, 0 }
		    };

		    int ch;
		    while ((ch = getopt_long(argc, argv, "tn:x:c", opts, NULL)) != -1) {
			    switch (ch) {
			    case 'n':
				    max_entries = strtoul(optarg, NULL, 0);
				    break;
			    case 'x':
				    path = optarg;
				    break;
			    case 't':
				    docounters = false;
				    break;
			    case 'c':
				    docounters = true;
				    break;
			    default:
				    usage();
			    }
			    ;
		    }

		    int fd;
		    uintptr_t addr;
		    size_t sz;

		    fd = ksancov_open();
		    if (fd < 0) {
			    perror("ksancov_open");
			    return errno;
		    }
		    fprintf(stderr, "opened ksancov on fd %i\n", fd);

		    uintptr_t e;
		    ret = ksancov_map_edgemap(fd, &e, NULL);
		    if (ret) {
			    perror("ksancov map counters\n");
			    return ret;
		    }
		    struct ksancov_edgemap *map = (void *)e;
		    fprintf(stderr, "nedges (edgemap) = %u\n", map->nedges);

		    if (docounters) {
			    ret = ksancov_mode_counters(fd);
			    if (ret) {
				    perror("ksancov set mode\n");
				    return ret;
			    }
		    } else {
			    ret = ksancov_mode_trace(fd, max_entries);
			    if (ret) {
				    perror("ksancov set mode\n");
				    return ret;
			    }
		    }

		    ret = ksancov_map(fd, &addr, &sz);
		    if (ret) {
			    perror("ksancov map");
			    return ret;
		    }
		    fprintf(stderr, "mapped to 0x%lx + %lu\n", addr, sz);

		    if (docounters) {
			    counters = (void *)addr;
			    fprintf(stderr, "nedges (counters) = %u\n", counters->nedges);
		    } else {
			    trace = (void *)addr;
			    fprintf(stderr, "maxpcs = %lu\n", ksancov_trace_max_pcs(trace));
		    }
		    header = (void *)addr;

		    if (path) {
			    int pid = fork();
			    if (pid == 0) {
				    /* child */

				    ret = ksancov_thread_self(fd);
				    if (ret) {
					    perror("ksancov thread");
					    return ret;
				    }

				    ksancov_reset(header);
				    ksancov_start(header);
				    ret = execl(path, path, 0);
				    perror("execl");

				    exit(1);
			    } else {
				    /* parent */
				    waitpid(pid, NULL, 0);
				    ksancov_stop(header);
			    }
		    } else {
			    ret = ksancov_thread_self(fd);
			    if (ret) {
				    perror("ksancov thread");
				    return ret;
			    }

			    ksancov_reset(header);
			    ksancov_start(header);
			    int ppid = getppid();
			    ksancov_stop(header);
			    fprintf(stderr, "ppid = %i\n", ppid);
		    }

		    if (docounters) {
			    for (size_t i = 0; i < counters->nedges; i++) {
				    size_t hits = counters->hits[i];
				    if (hits) {
					    fprintf(stderr, "0x%lx: %lu hits [idx %lu]\n", ksancov_edge_addr(map, i), hits, i);
				    }
			    }
		    } else {
			    size_t head = ksancov_trace_head(trace);
			    fprintf(stderr, "head = %lu\n", head);
			    for (uint32_t i = 0; i < head; i++) {
				    uintptr_t pc = ksancov_trace_entry(trace, i);
				    fprintf(stderr, "0x%lx\n", pc);
			    }
		    }

		    ret = close(fd);
		    fprintf(stderr, "close = %i\n", ret);

		    return 0;
	    }

/*
 *  endif
 # */
