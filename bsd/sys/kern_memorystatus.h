/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
/*!
	@header kern_memorystatus.h
	This header defines a kernel event subclass for the OSMemoryNotification API
 */

#ifndef SYS_KERN_MEMORYSTATUS_H
#define SYS_KERN_MEMORYSTATUS_H

#ifndef MACH_KERNEL_PRIVATE

#include <stdint.h>
#include <sys/time.h>
#include <sys/proc.h>

/*
 * Define Memory Status event subclass.
 * Subclass of KEV_SYSTEM_CLASS
 */

/*!
	@defined KEV_MEMORYSTATUS_SUBCLASS
	@discussion The kernel event subclass for memory status events.
*/
#define KEV_MEMORYSTATUS_SUBCLASS        3

enum {
	kMemoryStatusLevelNote = 1,
	kMemoryStatusSnapshotNote = 2
};

enum {
	kMemoryStatusLevelAny = -1,
	kMemoryStatusLevelNormal = 0,
	kMemoryStatusLevelWarning = 1,
	kMemoryStatusLevelUrgent = 2,
	kMemoryStatusLevelCritical = 3
};

typedef struct jetsam_priority_entry {
	pid_t pid;
	uint32_t flags;
	int32_t hiwat_pages;
	int32_t hiwat_reserved1;
	int32_t hiwat_reserved2;
	int32_t hiwat_reserved3;
} jetsam_priority_entry_t;

/*
** maximum killable processes to keep track of
*/
#define kMaxPriorityEntries 64 

typedef struct jetsam_snapshot_entry {
	pid_t pid;
	char name[MAXCOMLEN+1];
	uint32_t pages;
	uint32_t flags;
	uint8_t uuid[16];
} jetsam_snapshot_entry_t;

/*
** how many processes to snapshot
*/
#define kMaxSnapshotEntries 128 

typedef struct jetsam_kernel_stats {
	uint32_t free_pages;
	uint32_t active_pages;
	uint32_t inactive_pages;
	uint32_t purgeable_pages;
	uint32_t wired_pages;
} jetsam_kernel_stats_t;

/*
** This is a variable-length struct.
** Allocate a buffer of the size returned by the sysctl, cast to a jetsam_snapshot_t *
*/

typedef struct jetsam_snapshot {
	jetsam_kernel_stats_t stats;
	size_t entry_count;
	jetsam_snapshot_entry_t entries[1];
} jetsam_snapshot_t;

enum {
	kJetsamFlagsFrontmost =		(1 << 0),
	kJetsamFlagsKilled =		(1 << 1),
	kJetsamFlagsKilledHiwat =	(1 << 2)
};
#endif /* !MACH_KERNEL_PRIVATE */

#ifdef KERNEL
extern void kern_memorystatus_init(void) __attribute__((section("__TEXT, initcode")));
extern int jetsam_kill_top_proc(void);

extern int kern_memorystatus_wakeup;
extern int kern_memorystatus_level;

#endif /* KERNEL */
#endif /* SYS_KERN_MEMORYSTATUS_H */
