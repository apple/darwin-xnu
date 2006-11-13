/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <sys/param.h>
#include <mach/boolean.h>
#include <sys/time.h>
#include <sys/malloc.h>

#include "rangelist.h"

static enum rl_overlaptype rl_scan_from(struct rl_head *rangelist, off_t start, off_t end, struct rl_entry **overlap, struct rl_entry *range);
static void rl_collapse_forwards(struct rl_head *rangelist, struct rl_entry *range);
static void rl_collapse_backwards(struct rl_head *rangelist, struct rl_entry *range);
static void rl_collapse_neighbors(struct rl_head *rangelist, struct rl_entry *range);


#ifdef RL_DIAGNOSTIC
static void
rl_verify(struct rl_head *rangelist) {
	struct rl_entry *entry;
	off_t limit = 0;
	
	if (CIRCLEQ_EMPTY(rangelist)) return;
	entry = CIRCLEQ_FIRST(rangelist);
	while (1) {
		if (CIRCLEQ_NEXT(entry, rl_link) == entry) panic("rl_verify: circular rangelist?!");
		if ((limit > 0) && (entry->rl_start <= limit)) panic("rl_verify: bad entry start?!");
		if (entry->rl_end < entry->rl_start) panic("rl_verify: bad entry end?!");
		limit = entry->rl_end;
		if (entry == CIRCLEQ_LAST(rangelist)) return;
		entry = CIRCLEQ_NEXT(entry, rl_link);
	};
}
#endif



/*
 * Initialize a range list head
 */
void
rl_init(struct rl_head *rangelist)
{
    CIRCLEQ_INIT(rangelist);
}



/*
 * Add a range to the list
 */
void
rl_add(off_t start, off_t end, struct rl_head *rangelist)
{
	struct rl_entry *range;
	struct rl_entry *overlap;
	enum rl_overlaptype ovcase;

#ifdef RL_DIAGNOSTIC
	if (end < start) panic("rl_add: end < start?!");
#endif

	ovcase = rl_scan(rangelist, start, end, &overlap);
			
	/*
	 * Six cases:
	 *	0) no overlap
	 *	1) overlap == range
	 *	2) overlap contains range
	 *	3) range contains overlap
	 *	4) overlap starts before range
	 *	5) overlap ends after range
	 */
	switch (ovcase) {
		case RL_NOOVERLAP: /* 0: no overlap */
			/*
				* If the list was empty 'prev' is undisturbed and 'overlap' == NULL;
				* if the search hit a non-overlapping entry PAST the start of the
				* new range, 'prev' points to ITS predecessor, and 'overlap' points
				* to that entry:
				*/
			MALLOC(range, struct rl_entry *, sizeof(*range), M_TEMP, M_WAITOK);
			range->rl_start = start;
			range->rl_end = end;
			
			/* Link in the new range: */
			if (overlap) {
				CIRCLEQ_INSERT_AFTER(rangelist, overlap, range, rl_link);
			} else {
				CIRCLEQ_INSERT_HEAD(rangelist, range, rl_link);
			}
			
			/* Check to see if any ranges can be combined (possibly including the immediately
			   preceding range entry)
			 */
			rl_collapse_neighbors(rangelist, range);
			break;

		case RL_MATCHINGOVERLAP: /* 1: overlap == range */
		case RL_OVERLAPCONTAINSRANGE: /* 2: overlap contains range */
			range = overlap; /* for debug output below */
			break;

		case RL_OVERLAPISCONTAINED: /* 3: range contains overlap */
			/*
			 * Replace the overlap with the new, larger range:
			 */
			overlap->rl_start = start;
			overlap->rl_end = end;
			rl_collapse_neighbors(rangelist, overlap);
			range = overlap; /* for debug output below */
			break;

		case RL_OVERLAPSTARTSBEFORE: /* 4: overlap starts before range */
			/*
			 * Expand the overlap area to cover the new range:
			 */
			overlap->rl_end = end;
			rl_collapse_forwards(rangelist, overlap);
			range = overlap; /* for debug output below */
			break;

		case RL_OVERLAPENDSAFTER: /* 5: overlap ends after range */
			/*
			 * Expand the overlap area to cover the new range:
			 */
			overlap->rl_start = start;
			rl_collapse_backwards(rangelist, overlap);
			range = overlap; /* for debug output below */
			break;
	}

#ifdef RL_DIAGNOSTIC
	rl_verify(rangelist);
#endif
}



/*
 * Remove a range from a range list.
 *
 * Generally, find the range (or an overlap to that range)
 * and remove it (or shrink it), then wakeup anyone we can.
 */
void
rl_remove(off_t start, off_t end, struct rl_head *rangelist)
{
	struct rl_entry *range, *next_range, *overlap, *splitrange;
	int ovcase, moretotest;

#ifdef RL_DIAGNOSTIC
	if (end < start) panic("rl_remove: end < start?!");
#endif

	if (CIRCLEQ_EMPTY(rangelist)) {
		return;
	};
        
	range = CIRCLEQ_FIRST(rangelist);
	while ((ovcase = rl_scan_from(rangelist, start, end, &overlap, range))) {
		switch (ovcase) {

		case RL_MATCHINGOVERLAP: /* 1: overlap == range */
			CIRCLEQ_REMOVE(rangelist, overlap, rl_link);
			FREE(overlap, M_TEMP);
			break;

		case RL_OVERLAPCONTAINSRANGE: /* 2: overlap contains range: split it */
			if (overlap->rl_start == start) {
				overlap->rl_start = end + 1;
				break;
			};
			
			if (overlap->rl_end == end) {
				overlap->rl_end = start - 1;
				break;
			};
			
			/*
			* Make a new range consisting of the last part of the encompassing range
			*/
			MALLOC(splitrange, struct rl_entry *, sizeof *splitrange, M_TEMP, M_WAITOK);
			splitrange->rl_start = end + 1;
			splitrange->rl_end = overlap->rl_end;
			overlap->rl_end = start - 1;
			
			/*
			* Now link the new entry into the range list after the range from which it was split:
			*/
			CIRCLEQ_INSERT_AFTER(rangelist, overlap, splitrange, rl_link);
			break;

		case RL_OVERLAPISCONTAINED: /* 3: range contains overlap */
			moretotest = (overlap != CIRCLEQ_LAST(rangelist));
#ifdef RL_DIAGNOSTIC
			if (CIRCLEQ_NEXT(overlap, rl_link) == overlap) panic("rl_remove: circular range list?!");
#endif
			next_range = CIRCLEQ_NEXT(overlap, rl_link);	/* Check before discarding overlap entry */
			CIRCLEQ_REMOVE(rangelist, overlap, rl_link);
			FREE(overlap, M_TEMP);
			if (moretotest) {
				range = next_range;
				continue;
			};
			break;

		case RL_OVERLAPSTARTSBEFORE: /* 4: overlap starts before range */
			moretotest = (overlap != CIRCLEQ_LAST(rangelist));
			overlap->rl_end = start - 1;
			if (moretotest) {
#ifdef RL_DIAGNOSTIC
				if (CIRCLEQ_NEXT(overlap, rl_link) == overlap) panic("rl_remove: circular range list?!");
#endif
				range = CIRCLEQ_NEXT(overlap, rl_link);
				continue;
			};
			break;

		case RL_OVERLAPENDSAFTER: /* 5: overlap ends after range */
			overlap->rl_start = (end == RL_INFINITY ? RL_INFINITY : end + 1);
			break;
		}
		break;
	}

#ifdef RL_DIAGNOSTIC
	rl_verify(rangelist);
#endif
}



/*
 * Scan a range list for an entry in a specified range (if any):
 *
 * NOTE: this returns only the FIRST overlapping range.
 *	     There may be more than one.
 */

enum rl_overlaptype
rl_scan(struct rl_head *rangelist,
		off_t start,
		off_t end,
		struct rl_entry **overlap) {
		
	if (CIRCLEQ_EMPTY(rangelist)) {
		*overlap = NULL;
		return RL_NOOVERLAP;
	};
        
	return rl_scan_from(rangelist, start, end, overlap, CIRCLEQ_FIRST(rangelist));	
}



/*
 * Walk the list of ranges for an entry to
 * find an overlapping range (if any).
 *
 * NOTE: this returns only the FIRST overlapping range.
 *	     There may be more than one.
 */
static enum rl_overlaptype
rl_scan_from(struct rl_head *rangelist,
			 off_t start,
			 off_t end,
			 struct rl_entry **overlap,
			struct rl_entry *range)
{
	if (CIRCLEQ_EMPTY(rangelist)) {
		*overlap = NULL;
		return RL_NOOVERLAP;
	};
        
#ifdef RL_DIAGNOSTIC
		rl_verify(rangelist);
#endif

	*overlap = range;
        
	while (1) {
		/*
		 * OK, check for overlap
		 *
		 * Six cases:
		 *	0) no overlap (RL_NOOVERLAP)
		 *	1) overlap == range (RL_MATCHINGOVERLAP)
		 *	2) overlap contains range (RL_OVERLAPCONTAINSRANGE)
		 *	3) range contains overlap (RL_OVERLAPISCONTAINED)
		 *	4) overlap starts before range (RL_OVERLAPSTARTSBEFORE)
		 *	5) overlap ends after range (RL_OVERLAPENDSAFTER)
		 */
		if (((range->rl_end != RL_INFINITY) && (start > range->rl_end)) ||
			((end != RL_INFINITY) && (range->rl_start > end))) {
			/* Case 0 (RL_NOOVERLAP), at least with the current entry: */
			if ((end != RL_INFINITY) && (range->rl_start > end)) {
				return RL_NOOVERLAP;
			};
			
			/* Check the other entries in the list: */
			if (range == CIRCLEQ_LAST(rangelist)) {
				return RL_NOOVERLAP;
			};
#ifdef RL_DIAGNOSTIC
			if (CIRCLEQ_NEXT(range, rl_link) == range) panic("rl_scan_from: circular range list?!");
#endif
			*overlap = range = CIRCLEQ_NEXT(range, rl_link);
			continue;
		}
		
		if ((range->rl_start == start) && (range->rl_end == end)) {
			/* Case 1 (RL_MATCHINGOVERLAP) */
			return RL_MATCHINGOVERLAP;
		}
		
		if ((range->rl_start <= start) &&
			(end != RL_INFINITY) &&
			((range->rl_end >= end) || (range->rl_end == RL_INFINITY))) {
				/* Case 2 (RL_OVERLAPCONTAINSRANGE) */
			return RL_OVERLAPCONTAINSRANGE;
		}
		
		if ((start <= range->rl_start) &&
			((end == RL_INFINITY) ||
			 ((range->rl_end != RL_INFINITY) && (end >= range->rl_end)))) {
			/* Case 3 (RL_OVERLAPISCONTAINED) */
			return RL_OVERLAPISCONTAINED;
		}
		
		if ((range->rl_start < start) &&
			((range->rl_end >= start) || (range->rl_end == RL_INFINITY))) {
			/* Case 4 (RL_OVERLAPSTARTSBEFORE) */
			return RL_OVERLAPSTARTSBEFORE;
		}
		
		if ((range->rl_start > start) &&
			(end != RL_INFINITY) &&
			((range->rl_end > end) || (range->rl_end == RL_INFINITY))) {
			/* Case 5 (RL_OVERLAPENDSAFTER) */
			return RL_OVERLAPENDSAFTER;
		}

		/* Control should never reach here... */
#ifdef RL_DIAGNOSTIC
		panic("rl_scan_from: unhandled overlap condition?!");
#endif
	}
        
	return RL_NOOVERLAP;
}


static void
rl_collapse_forwards(struct rl_head *rangelist, struct rl_entry *range) {
    struct rl_entry *next_range;
    
    while (1) {
		if (range == CIRCLEQ_LAST(rangelist)) return;
    
#ifdef RL_DIAGNOSTIC
		if (CIRCLEQ_NEXT(range, rl_link) == range) panic("rl_collapse_forwards: circular range list?!");
#endif
		next_range = CIRCLEQ_NEXT(range, rl_link);
        if ((range->rl_end != RL_INFINITY) && (range->rl_end < next_range->rl_start - 1)) return;

        /* Expand this range to include the next range: */
        range->rl_end = next_range->rl_end;
        
        /* Remove the now covered range from the list: */
        CIRCLEQ_REMOVE(rangelist, next_range, rl_link);
        FREE(next_range, M_TEMP);

#ifdef RL_DIAGNOSTIC
		rl_verify(rangelist);
#endif
    };
}



static void
rl_collapse_backwards(struct rl_head *rangelist, struct rl_entry *range) {
    struct rl_entry *prev_range;
    
    while (1) {
        if (range == CIRCLEQ_FIRST(rangelist)) return;
        
#ifdef RL_DIAGNOSTIC
		if (CIRCLEQ_PREV(range, rl_link) == range) panic("rl_collapse_backwards: circular range list?!");
#endif
        prev_range = CIRCLEQ_PREV(range, rl_link);
        if (prev_range->rl_end < range->rl_start - 1) {
#ifdef RL_DIAGNOSTIC
			rl_verify(rangelist);
#endif
        	return;
        };
        
        /* Expand this range to include the previous range: */
        range->rl_start = prev_range->rl_start;
    
        /* Remove the now covered range from the list: */
        CIRCLEQ_REMOVE(rangelist, prev_range, rl_link);
        FREE(prev_range, M_TEMP);
    };
}



static void
rl_collapse_neighbors(struct rl_head *rangelist, struct rl_entry *range)
{
    rl_collapse_forwards(rangelist, range);
    rl_collapse_backwards(rangelist, range);
}
