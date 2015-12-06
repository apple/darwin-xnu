/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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
#include <net/if_var.h>
#include <net/net_perf.h>
#include <netinet/in_var.h>
#include <sys/sysctl.h>

static void ip_perf_record_stats(net_perf_t *npp, struct timeval *tv1,
	struct timeval *tv2, uint64_t num_pkts);
static void update_bins(net_perf_t *npp, uint64_t bins);

void net_perf_start_time(net_perf_t *npp, struct timeval *tv)
{
#pragma unused(npp)
	microtime(tv);
}

void net_perf_measure_time(net_perf_t *npp, struct timeval *start, uint64_t num_pkts)
{
	struct timeval stop;
	microtime(&stop);
	ip_perf_record_stats(npp, start, &stop, num_pkts);
}

static void
ip_perf_record_stats(net_perf_t *npp, struct timeval *tv1, struct timeval *tv2, uint64_t num_pkts)
{
	struct timeval tv_diff;
	uint64_t usecs;
	timersub(tv2, tv1, &tv_diff);
	usecs = tv_diff.tv_sec * 1000000ULL + tv_diff.tv_usec;
	OSAddAtomic64(usecs, &npp->np_total_usecs);
	OSAddAtomic64(num_pkts, &npp->np_total_pkts);
}

static void
update_bins(net_perf_t *npp, uint64_t bins)
{
	bzero(&npp->np_hist_bars, sizeof(npp->np_hist_bars));

	for (int i = 1, j = 0; i <= 64 && j < NET_PERF_BARS; i++) {
		if (bins & 0x1) {
			npp->np_hist_bars[j] = i;
			j++;
		}
		bins >>= 1;
	}
}

void
net_perf_initialize(net_perf_t *npp, uint64_t bins)
{
	bzero(npp, sizeof(net_perf_t));
	/* initialize np_hist_bars array */
	update_bins(npp, bins);
}

void
net_perf_histogram(net_perf_t *npp, uint64_t num_pkts)
{
	if (num_pkts <= npp->np_hist_bars[0]) {
		OSAddAtomic64(num_pkts, &npp->np_hist1);
	} else if (npp->np_hist_bars[0] < num_pkts && num_pkts <= npp->np_hist_bars[1]) {
		OSAddAtomic64(num_pkts, &npp->np_hist2);
	} else if (npp->np_hist_bars[1] < num_pkts && num_pkts <= npp->np_hist_bars[2]) {
		OSAddAtomic64(num_pkts, &npp->np_hist3);
	} else if (npp->np_hist_bars[2] < num_pkts && num_pkts <= npp->np_hist_bars[3]) {
		OSAddAtomic64(num_pkts, &npp->np_hist4);
	} else if (npp->np_hist_bars[3] < num_pkts) {
		OSAddAtomic64(num_pkts, &npp->np_hist5);
	}
}

boolean_t
net_perf_validate_bins(uint64_t bins)
{
	return (NET_PERF_BARS == __builtin_popcountll(bins));
}

