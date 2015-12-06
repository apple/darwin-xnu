/*
 * Copyright (c) 2001-2014 Apple Computer, Inc. All rights reserved.
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
#ifndef _HFS_RANGELIST_H_
#define _HFS_RANGELIST_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/types.h>
#include <sys/queue.h>

enum rl_overlaptype {
    RL_NOOVERLAP = 0,		/* 0 */
    RL_MATCHINGOVERLAP,		/* 1 */
    RL_OVERLAPCONTAINSRANGE,	/* 2 */
    RL_OVERLAPISCONTAINED,	/* 3 */
    RL_OVERLAPSTARTSBEFORE,	/* 4 */
    RL_OVERLAPENDSAFTER		/* 5 */
};

#define RL_INFINITY INT64_MAX

TAILQ_HEAD(rl_head, rl_entry);

struct rl_entry {
    TAILQ_ENTRY(rl_entry) rl_link;
    off_t rl_start;
    off_t rl_end;
};

__BEGIN_DECLS
void rl_init(struct rl_head *rangelist);
void rl_add(off_t start, off_t end, struct rl_head *rangelist);
void rl_remove(off_t start, off_t end, struct rl_head *rangelist);
void rl_remove_all(struct rl_head *rangelist);
enum rl_overlaptype rl_scan(struct rl_head *rangelist,
							off_t start,
							off_t end,
							struct rl_entry **overlap);
enum rl_overlaptype rl_overlap(const struct rl_entry *range, 
							   off_t start, off_t end);

static __attribute__((pure)) inline
off_t rl_len(const struct rl_entry *range)
{
	return range->rl_end - range->rl_start + 1;
}

void rl_subtract(struct rl_entry *a, const struct rl_entry *b);

static inline struct rl_entry rl_make(off_t start, off_t end)
{
	return (struct rl_entry){ .rl_start = start, .rl_end = end };
}

__END_DECLS

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* ! _HFS_RANGELIST_H_ */
