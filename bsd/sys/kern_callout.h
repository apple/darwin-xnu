/*
 * Copyright (c) 2008 Apple Computer, Inc. All rights reserved.
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

#ifndef KPI_KERN_CALLOUT_H
#define KPI_KERN_CALLOUT_H

#ifdef KERNEL

/*
 * Default sample threshold for validity
 */
#define MA_SMA_SAMPLES	10			/* simple moving average */

/*
 * Flags bits for the ma_flags field
 */
#define	KCO_MA_F_SMA		0x00000001	/* Simple moving average */
#define	KCO_MA_F_WMA		0x00000002	/* Weighted moving average */
#define	KCO_MA_F_NEEDS_INIT	0x80000000	/* Need initialization */

struct kco_moving_average {
	int		ma_flags;		/* flags */
	uint64_t	ma_sma;			/* simple over MA_SMA_SAMPLES*/
	uint64_t	ma_old_sma;		/* previous value */
	uint64_t	ma_sma_samples[MA_SMA_SAMPLES];	/* sample history */
	int32_t		ma_sma_threshold;	/* trigger delta (%) */
	int		ma_sma_trigger_count;	/* number of time triggered */
	uint64_t	ma_wma;			/* weighted */
	uint64_t	ma_old_wma;		/* previous value */
	int		ma_wma_weight;		/* weighting (< 100) */
	int32_t		ma_wma_threshold;	/* trigger delta (%) */
	int		ma_wma_trigger_count;	/* number of time triggered */
};

__BEGIN_DECLS
int kco_ma_addsample(struct kco_moving_average *map, uint64_t sample_time);
void kco_ma_init(struct kco_moving_average *map, int32_t threshold, int kind);
int kco_ma_info(struct kco_moving_average *map, int kind, uint64_t *averagep, uint64_t *old_averagep, int32_t *thresholdp, int *countp);
__END_DECLS

#endif /* KERNEL */

#endif /* KPI_KERN_CONTROL_H */
