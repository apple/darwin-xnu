/*
 * Copyright (c) 2004-2007 Apple Inc. All rights reserved.
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

/*
 * Kernel callout related functions, including moving average calculation
 * to permit the kernel to know about insufficiently responsive user space
 * processes.
 */

#include <string.h>		/* memove, memset */
#include <stdint.h>		/* uint64_t */
#include <sys/kern_callout.h>

/*
 * kco_ma_init
 *
 * Initialize a moving average structure for use
 *
 * Parameters:	map			Pointer to the moving average state
 *		threshold		Threshold % at which to trigger (>100)
 *		kind			Kind of trigger(s) to set
 *
 * Returns:	(void)
 *
 * Notes:	The number of samples in a simple moving average is not
 *		controllable; this might be a future direction.
 *
 *		The simple and weighted thresholds are not separately
 *		controllable; this might be a future direction, but
 *		will likely be unnecessary due to one type being in use
 *		at a time in the most likely scenarios.
 */
void
kco_ma_init(struct kco_moving_average *map, int32_t threshold, int kind)
{
	memset(map, 0, sizeof(*map));

	/* per algorithm init required */
	map->ma_flags |= KCO_MA_F_NEEDS_INIT;

	/* set algorithm selector flags */
	map->ma_flags |= kind;

	/* set thresholds */
	map->ma_sma_threshold = threshold;
	map->ma_wma_threshold = threshold;
}


/*
 * kco_ma_info
 *
 * Report on the current moving average information; this is typically only
 * called after a trigger event.
 *
 * Parameters:	map			Pointer to the moving average state
 *		kind			Kind of trigger to report on
 *		averagep		Pointer to area to receive current
 *		old_averagep		Pointer to area to receive previous
 *		thresholdp		Pointer to area to receive threshold
 *
 * Returns:	0			Information not available
 *		1			Information retrieved
 *
 * Notes:	You can only retrieve one kind of average information at a
 *		time; if you are collecting multiple types, then you must
 *		call this function one time for each type you are interested
 *		in obtaining.
 */
int
kco_ma_info(struct kco_moving_average *map, int kind, uint64_t *averagep, uint64_t *old_averagep, int32_t *thresholdp, int *countp)
{
	uint64_t	average;
	uint64_t	old_average;
	int32_t		threshold;
	int		count;

	/* Not collecting this type of data  or no data yet*/
	if (!(map->ma_flags & kind) || (map->ma_flags & KCO_MA_F_NEEDS_INIT))
		return(0);

	switch(kind) {
	case KCO_MA_F_SMA:
		average = map->ma_sma;
		old_average = map->ma_old_sma;
		threshold = map->ma_sma_threshold;
		count = map->ma_sma_trigger_count;
		break;

	case KCO_MA_F_WMA:
		average = map->ma_wma;
		old_average = map->ma_old_wma;
		threshold = map->ma_wma_threshold;
		count = map->ma_wma_trigger_count;
		break;

	default:
		/*
		 * Asking for data we don't have or more than one kind of
		 * data at the same time.
		 */
		return(0);
	}

	if (averagep != NULL)
		*averagep = average;
	if (old_averagep != NULL)
		*old_averagep = old_average;
	if (thresholdp != NULL)
		*thresholdp = threshold;
	if (countp != NULL)
		*countp = count;

	return(1);
}


/*
 * kco_ma_addsample
 *
 * Accumulate a sample into a moving average
 *
 * Parameters:	map			Pointer to the moving average state
 *		sample_time		latency delta time
 *
 * Returns:	0			Nothing triggered
 *		!0			Bitmap of KCO_MA_F_* flags for the
 *						algorithms which triggered
 *
 * Notes:	Add a delta time sample to the moving average; this function
 *		will return bits for each algorithm which went over its
 *		trigger threshold as a result of receiving the sample.
 *		Callers can then log/complain/panic over the unresponsive
 *		process to which they are calling out.
 */
int
kco_ma_addsample(struct kco_moving_average *map, uint64_t sample_time)
{
	int	triggered = 0;
	int	do_init = (map->ma_flags & KCO_MA_F_NEEDS_INIT);

	/*
	 * SIMPLE MOVING AVERAGE
	 *
	 * Compute simple moving average over MA_SMA_SAMPLES; incremental is
	 * cheaper than re-sum.
	 */
	if (map->ma_flags & KCO_MA_F_SMA) {
		map->ma_old_sma = map->ma_sma;

		map->ma_sma = ((map->ma_sma * MA_SMA_SAMPLES) - map->ma_sma_samples[0] + sample_time) / MA_SMA_SAMPLES;
		memmove(&map->ma_sma_samples[1], &map->ma_sma_samples[0], sizeof(map->ma_sma_samples[0]) *(MA_SMA_SAMPLES - 1));
		map->ma_sma_samples[0] = sample_time;
		/*
		 * Check if percentage change exceeds the allowed trigger
		 * threshold; this will only happen if the sample time
		 * increases more than an acceptable amount; decreases will
		 * not cause a trigger (but will decrease the overall average,
		 * which can cause a trigger the next time).
		 *
		 * Note:	We don't start triggering on the simple moving
		 *		average until after we have enough samples for
		 *		the delta to be statistically valid; this is
		 *		defined to be MA_SMA_SAMPLES.
		 */
		if (map->ma_sma_samples[MA_SMA_SAMPLES-1] && ((int)((map->ma_sma * 100) / map->ma_old_sma)) > map->ma_sma_threshold) {
			triggered |= KCO_MA_F_SMA;
			map->ma_sma_trigger_count++;
		}
	}

	/*
	 * WEIGHTED MOVING AVERAGE
	 *
	 * Compute the weighted moving average.  Do this by averaging over
	 * two values, one with a lesser weighting than the other; the lesser
	 * weighted value is the persistent historical value, whose sample
	 * weight decreases over time, the older the samples get.  Be careful
	 * here to permit strict integer artimatic.
	 */
	if (map->ma_flags & KCO_MA_F_WMA) {
		map->ma_old_wma = map->ma_wma;

		/* Prime the pump, if necessary */
		if (do_init)
			map->ma_old_wma = sample_time;

		map->ma_wma = ((((map->ma_wma * 90) + sample_time * ((100*2) - 90))/100) / 2);

		/*
		 * Check if percentage change exceeds the allowed trigger
		 * threshold; this will only happen if the sample time
		 * increases more than an acceptable amount; decreases will
		 * not cause a trigger (but will decrease the overall average,
		 * which can cause a trigger the next time).
		 */
		if (((int)(((map->ma_wma * 100) / map->ma_old_wma))) > map->ma_wma_threshold) {
			triggered |= KCO_MA_F_WMA;
			map->ma_wma_trigger_count++;
		}
	}

	if (do_init)
		map->ma_flags &= ~KCO_MA_F_NEEDS_INIT;

	return (triggered);
}
